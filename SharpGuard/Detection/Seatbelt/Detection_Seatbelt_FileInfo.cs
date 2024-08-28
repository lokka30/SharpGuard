using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using SharpGuard.Event;
using SharpGuard.File;
using SharpGuard.Log;

namespace SharpGuard.Detection.Seatbelt
{
    /// <summary>
    /// Attempts to detect when Seatbelt's FileInfo command is ran with the <code>-full</code> parameter
    /// (no filter used). This is achieved by monitoring files of interest.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class Detection_FileAccessPattern : Detection
    {

        /// <summary>
        /// Format of the alert description table columns. Left-align values for readability.
        /// </summary>
        private const string DESCRIBED_TABLE_FMT = "| {0,-24} | #{1,-8} | {2,-10} | {3,-8} |\n";

        /// <summary>
        /// File names of interest.
        /// Located inside 'C:\Windows\System32' or any subdirectories.
        /// All strings here must be lowercase!
        /// </summary>
        private static readonly string[] fileNames = {
            "coremessaging.dll",
            "afd.sys",
            "mrxdav.sys",
            "dssvc.dll",
            "gdiplus.dll",
            "gpprefcl.dll",
            "ntoskrnl.exe",
            "pcadm.dll",
            "rpcrt4.dll",
            "shedsvc.dll",
            "seclogon.dll",
            "win32k.sys",
            "win32kfull.sys",
            "winload.exe",
            "winsrv.dll"
        };

        /// <summary>
        /// Directory where the files of interest are located (somewhere within).
        /// Again, the files don't have to be directly inside this directory, it can be in any
        /// subdirectory of that, recursively.
        /// </summary>
        private const string dirName = @"C:\Windows\System32";

        /// <summary>
        /// Time between batches being separated, milliseconds
        /// </summary>
        public static readonly int millisPerBatch = 10_000;

        /// <summary>
        /// Time between scheduled checks, milliseconds
        /// </summary>
        public static readonly int millisPerCheck = 05_000;

        /// <summary>
        /// Lower bound for the time key; time keys lower than this are discarded
        /// </summary>
        public static readonly int timeKeyLowerBound = -2;

        /// <summary>
        /// Count # required to trigger alert
        /// </summary>
        public static readonly int countTriggerBound = 8;

        /// <summary>
        /// Collection of file system watchers in use.
        /// This is used when the detection is stopped, so it can dispose of the FSwatcher objects.
        /// </summary>
        private LinkedList<FileSystemWatcher> Watchers { get; init; } = new();

        /// <summary>
        /// 30 second batches of access frequencies.
        /// 
        /// Format: <code>Dictionary(string FileName, Dictionary(int TimeKey, int AccessCount))</code>
        /// </summary>
        private ConcurrentDictionary<string, ConcurrentDictionary<int, int>> AccFreqMap { get; init; } = new();

        /// <summary>
        /// Every <code>millisPerBatch</code> seconds, remove any old time key entries, and make each existing time key entry older.
        /// </summary>
        private Timer? AccFreqMapUpdateTimer { get; set; } = null;

        /// <summary>
        /// Every <code>millisPerCheck</code> seconds, check all keys to see if all counts are suspicious.
        /// </summary>
        private Timer? MaliciousCheckerTimer { get; set; } = null;

        /// <summary>
        /// Generate a readable string describing the access frequency map, tabulated.
        /// </summary>
        /// <returns>Readable string describing the access frequency map</returns>
        public string DescribeAccFreqMap()
        {
            try
            {
                lock (AccFreqMap)
                {
                    StringBuilder sb = new("Access Frequency Map Overview:\n");
                    sb.Append($"{new string('-', 30)}\n");
                    sb.Append(string.Format(DESCRIBED_TABLE_FMT, "File Name", "Batch ID", "Age", "Count"));
                    sb.Append(string.Format(DESCRIBED_TABLE_FMT, new string('-', 24), new string('-', 8), new string('-', 10), new string('-', 8)));

                    foreach (string fileName in AccFreqMap.Keys)
                    {
                        ConcurrentDictionary<int, int> batchAgeToCount = AccFreqMap[fileName];
                        foreach (int batchAgeId in batchAgeToCount.Keys.Order())
                        {
                            double batchAgeMins = Math.Round(batchAgeId == 0 ? 0f : batchAgeId * -millisPerBatch / 60_000d, 2);
                            int batchCount = batchAgeToCount[batchAgeId];
                            sb.Append(string.Format(DESCRIBED_TABLE_FMT, fileName, batchAgeId, $"{batchAgeMins}m ago", $"{batchCount} hits"));
                        }
                    }

                    return sb.ToString();
                }
            }
            catch (Exception ex)
            {
                // This method isn't crucial, so let's not rethrow this exception, instead, make it clear that it wasn't able to run.
                Logger.WriteErr("Detection_Seatbelt_FileInfo", $"Caught exception: {ex.Message}; Stack Trace:\n{ex.StackTrace ?? "N/A"}");
                return $"Unable to describe acc freq map: {ex.Message}";
            }
        }

        /// <summary>
        /// Construct the detection
        /// </summary>
        /// <param name="onAlert">delegated to abstract class</param>
        /// <param name="eventHandler">delegated to abstract class</param>
        public Detection_FileAccessPattern(Action<Alert> onAlert, WinEventHandler eventHandler) : base(onAlert, eventHandler)
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "Class", () => "Object initialized");
        }

        /// <summary>
        /// Start the detection.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the detection is already enabled</exception>
        public override void Start()
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "Start", () => "Starting detection...");

            // Don't start if already enabled
            if (Enabled)
            {
                throw new InvalidOperationException("Detection is already enabled");
            }

            Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "Start", () => "Initializing detection...");

            // If any of these fail, clean up as much as possible, and rethrow exception.
            try
            {
                InitialiseAccFreqMap();
                StartTimers();
                StartWatchers();
            }
            catch (Exception ex)
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "Start", () => "Caught exception: " + ex.Message);
                Stop();
                throw;
            }

            // Update enabled state here.
            Enabled = true;
            Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "Start", () => "Detection initialized.");
        }

        /// <summary>
        /// Initialize the access frequency map with each file name paired with a child dictionary of values (0, 0).
        /// </summary>
        private void InitialiseAccFreqMap()
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "InitialiseAccFreqMap", () => "Method called...");
            lock (AccFreqMap)
            {
                foreach (string fileName in fileNames)
                {
                    ConcurrentDictionary<int, int> countByTimeMap = new();
                    countByTimeMap.TryAdd(0, 0); // no Add method so can't initialize this inline :(
                    AccFreqMap.TryAdd(fileName, countByTimeMap);
                    Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "InitialiseAccFreqMap", () => $"TryAdd fileName = {fileName} set 0,0");
                }
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "InitialiseAccFreqMap", () => $"Initialized map with {AccFreqMap.Count} vals.");
            }
        }

        /// <summary>
        /// Start all of the timers required to run this detection
        /// </summary>
        private void StartTimers()
        {
            try
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "StartTimers", () => "Method called...");

                // Initialize AccFreqMapUpdateTask
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "StartTimers", () => "Initializing AccFreqMapUpdateTask...");
                AccFreqMapUpdateTimer = new Timer(
                    callback: o => HandleAccFreqMapUpdate(),
                    state: null,
                    dueTime: 0,
                    period: millisPerBatch); // millis

                // Initialize MaliciousCheckerTask
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "StartTimers", () => "Initializing MaliciousCheckerTask...");
                MaliciousCheckerTimer = new Timer(
                    callback: o => HandleMaliciousChecker(),
                    state: null,
                    dueTime: 0,
                    period: millisPerCheck); // millis

                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "StartTimers", () => "Initialized all timers.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("StartTimers", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
                throw;
            }

        }

        /// <summary>
        /// Handles the AccFreqMap checker timer action.
        /// </summary>
        private void HandleAccFreqMapUpdate()
        {

            try
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MAPUPDATE, "HandleAccFreqMapUpdate", () => "Method called...");

                lock (AccFreqMap)
                {
                    foreach (string key in AccFreqMap.Keys)
                    {
                        ConcurrentDictionary<int, int> accFreq = AccFreqMap[key];
                        foreach (int timeKey in accFreq.Keys.ToArray().OrderDescending())
                        {
                            // If the time key is below the bound desired (timeKeyLowerBound), simply discard it, as it's no longer needed.
                            // Else, drop-down / age each batch, decrementing its ID and reinitializing ID=0 to a count value of 0.
                            if (timeKey < timeKeyLowerBound)
                            {
                                // Try remove.
                                accFreq.TryRemove(timeKey, out int _);

                                // Completed!
                                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MAPUPDATE, "HandleAccFreqMapUpdate", () => $"TryRemove timeKey={timeKey}.");
                            }
                            else
                            {
                                // Drop-down
                                accFreq[timeKey - 1] = accFreq[timeKey];

                                // Reinitialize
                                if (timeKey == 0)
                                {
                                    accFreq[timeKey] = 0;
                                    Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MAPUPDATE, "HandleAccFreqMapUpdate", () => $"Reset timeKey={timeKey} to {accFreq[timeKey]}.");
                                }

                                // Completed!
                                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MAPUPDATE, "HandleAccFreqMapUpdate", () => $"Drop-down to timeKey={timeKey - 1}.");
                            }
                        }
                    }
                }

                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MAPUPDATE, "HandleAccFreqMapUpdate", () => "Method complete.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("HandleAccFreqMapUpdate", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
            }
        }

        /// <summary>
        /// Start the file system watchers.
        /// </summary>
        private void StartWatchers()
        {
            try
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "StartWatchers", () => "Method called...");
                foreach (string fileName in fileNames)
                {
                    Watchers.AddLast(
                        FileUtils.Watch(dirName, fileName, wfe => HandleFileEvent(wfe))
                    );
                }
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "StartWatchers", () => "Method complete.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("StartWatchers", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
                throw;
            }
        }

        /// <summary>
        /// Stop the detection. Even if not enabled, it will at least try clean up, especially if it wasn't able to start properly.
        /// </summary>
        public override void Stop()
        {
            if(!Enabled)
            {
                Logger.WriteWarn("Seatbelt-FileInfo", "Detection is stopping without being fully enabled (unsafe state). Continuing anyways to cleanup.");
            }

            try
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "Stop", () => "Stopping detection...");
                DisposeWatchers();
                DisposeTimers();
                Enabled = false;
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "Stop", () => "Stopped detection.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("Stop", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
                throw;
            }
        }

        /// <summary>
        /// Clean up the file system watcher objects.
        /// </summary>
        private void DisposeWatchers()
        {
            try
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "DisposeWatchers", () => "Method called...");
                foreach (FileSystemWatcher watcher in Watchers)
                {
                    watcher.Dispose();
                }
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "DisposeWatchers", () => "Method complete.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("DisposeWatchers", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
                throw;
            }


        }

        /// <summary>
        /// Clean up the timers.
        /// </summary>
        private void DisposeTimers()
        {
            try
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "DisposeTimers", () => "Method called...");
                MaliciousCheckerTimer?.Dispose();
                AccFreqMapUpdateTimer?.Dispose();
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_GENERIC, "DisposeTimers", () => "Method complete.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("Handle", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
                throw;
            }
        }

        /// <summary>
        /// Handle a file system watched file event.
        /// </summary>
        /// <param name="wfe">Event information about a watched file of interest</param>
        private void HandleFileEvent(FileUtils.WatchedFileEvent wfe)
        {
            try
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_HANDLE, "Handle", () => $"Method called... wfe={wfe}");

                if (wfe.Type == FileUtils.FileEventType.ERROR || wfe.FileName.Length == 0)
                {
                    Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_HANDLE, "Handle", () => $"WFE type is error, msg={wfe.Descr}");
                    return;
                }

                lock (AccFreqMap)
                {
                    ConcurrentDictionary<int, int> countByTime = AccFreqMap[wfe.FileName.ToLower()];
                    int cbt = countByTime[0] + 1;
                    countByTime[0] = cbt;
                    Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_HANDLE, "Handle", () => $"Method complete. (countByTime = {countByTime}, cbt = {cbt})");
                }

                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_HANDLE, "Handle", () => "Delegating malicious activity checking to HandleMaliciousChecker");
                HandleMaliciousChecker();
            }
            catch (Exception ex)
            {
                Logger.WriteErr("Handle", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
                throw;
            }
        }

        /// <summary>
        /// Checks for malicious-looking file system activity, triggers alert if so
        /// </summary>
        private void HandleMaliciousChecker()
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MALCHECKER, "HandleMaliciousChecker", () => "Method called...");
            LinkedList<string> fileNamesWithWatchedEvent = new();

            try
            {
                lock (AccFreqMap)
                {
                    foreach (string fileName in AccFreqMap.Keys)
                    {
                        Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MALCHECKER, "HandleMaliciousChecker", () => "Checking key " + fileName);

                        int totalCount = 0;

                        ConcurrentDictionary<int, int> accFreq = AccFreqMap[fileName];
                        foreach (int timeKey in accFreq.Keys)
                        {
                            int count = accFreq[timeKey];
                            totalCount += count;
                            Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MALCHECKER, "HandleMaliciousChecker", () => $"timeKey={timeKey}, count={count}, total={totalCount}");
                        }

                        if (totalCount > 1)
                        {
                            Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MALCHECKER, "HandleMaliciousChecker", () => $"totalCount>1, so adding to watched event list");
                            fileNamesWithWatchedEvent.AddLast(fileName);
                        }
                    }

                    if (fileNamesWithWatchedEvent.Count >= countTriggerBound)
                    {
                        Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MALCHECKER, "HandleMaliciousChecker", () => $"High number of watched events, triggering detection!");
                        string shortDesc = $"Possible use of Seatbelt detected on this system judgying by file access patterns. Trigger count is {countTriggerBound}; matched {fileNamesWithWatchedEvent.Count} of {fileNames.Length} associated file names.";
                        string longDesc = $"Please see further details below.\n{DescribeAccFreqMap()}";
                        Alert dinfo = new(AlertType.SEATBELT_FILEINFO, shortDesc, longDesc);
                        OnAlert(dinfo);
                        WriteEvent(dinfo);
                    }
                }

                Logger.WriteDebug(DebugCategory.DETECTIONS_SEATBELT_FILEINFO_MALCHECKER, "HandleMaliciousChecker", () => "Method complete.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("HandleMaliciousChecker", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
                throw;
            }
        }

        /// <summary>
        /// Write alert to event handler
        /// </summary>
        /// <param name="alert">Alert information</param>
        private void WriteEvent(Alert alert)
        {
            try
            {
                EventID eventID = EventID.DETECTION_SEATBELT_FILEINFO;
                CategoryID catID = CategoryID.DETECTIONS;
                EventHandler.WriteEvent(alert.ToReadableString(), System.Diagnostics.EventLogEntryType.Warning, eventID, catID);
            }
            catch (Exception ex)
            {
                Logger.WriteErr("WriteEvent", $"Unable to write event: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
                // this method is not important so it will not rethrow ex.
            }
        }
    }
}
