using SharpGuard.Event;
using SharpGuard.File;
using SharpGuard.Log;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;

namespace SharpGuard.Detection
{
    /// <summary>
    /// Abstract class to share code between detections that monitor file access patterns as part of their alarms.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public abstract class Detection_FileAccessPattern : Detection
    {

        /// <summary>
        /// Format of the alert description table columns. Left-align values for readability.
        /// </summary>
        private const string DESCRIBED_TABLE_FMT = "| {0,-24} | #{1,-8} | {2,-10} | {3,-8} |\n";

        /// <summary>
        /// Name of the target thing being investigated, e.g., "Seatbelt-FileInfo"
        /// </summary>
        protected String TargetName { get; init; }

        /// <summary>
        /// Type of alert of the target, e.g. "SEATBELT_FILEINFO"
        /// </summary>
        protected AlertType TargetAlertType { get; init; }

        /// <summary>
        /// File names of interest.
        /// Located inside 'C:\Windows\System32' or any subdirectories.
        /// All strings here must be lowercase!
        /// </summary>
        protected string[] FileNames { get; init; }

        /// <summary>
        /// Directory where the files of interest are located (somewhere within).
        /// Again, the files don't have to be directly inside this directory, it can be in any
        /// subdirectory of that, recursively.
        /// </summary>
        protected string DirName { get; init; }

        /// <summary>
        /// Time between batches being separated, milliseconds
        /// </summary>
        protected int MillisPerBatch { get; init; }

        /// <summary>
        /// Time between scheduled checks, milliseconds
        /// </summary>
        protected int MillisPerCheck { get; init; }

        /// <summary>
        /// Lower bound for the time key; time keys lower than this are discarded
        /// </summary>
        protected int TimeKeyLowerBound { get; init; }

        /// <summary>
        /// Count # required to trigger alert
        /// </summary>
        protected int CountTriggerBound { get; init; }

        /// <summary>
        /// Collection of file system watchers in use.
        /// This is used when the detection is stopped, so it can dispose of the FSwatcher objects.
        /// </summary>
        private LinkedList<FileSystemWatcher> Watchers { get; init; } = new();

        /// <summary>
        /// <code>millisPerBatch</code>-millsecond batches of access frequencies.
        /// 
        /// Format: <code>Dictionary(string FileName, Dictionary(int TimeKey, int AccessCount))</code>
        /// </summary>
        protected ConcurrentDictionary<string, ConcurrentDictionary<int, int>> AccFreqMap { get; init; } = new();

        /// <summary>
        /// Event ID when logging alerts
        /// </summary>
        protected EventID Evid { get; init; }

        /// <summary>
        /// Every <code>millisPerBatch</code> seconds, remove any old time key entries, and make each existing time key entry older.
        /// </summary>
        private Timer? AccFreqMapUpdateTimer { get; set; } = null;

        /// <summary>
        /// Every <code>millisPerCheck</code> seconds, check all keys to see if all counts are suspicious.DETECTIONS_FILEACCESSPATTERN_GENERIC
        /// </summary>
        private Timer? MaliciousCheckerTimer { get; set; } = null;

        /// <summary>
        /// Generate a readable string describing the access frequency map, tabulated.
        /// </summary>
        /// <returns>Readable string describing the access frequency map</returns>
        protected string DescribeAccFreqMap()
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
                            double batchAgeMins = Math.Round(batchAgeId == 0 ? 0f : batchAgeId * -MillisPerBatch / 60_000d, 2);
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
                Logger.WriteErr("Detection_FileAccessPattern", $"Caught exception: {ex.Message}; Stack Trace:\n{ex.StackTrace ?? "N/A"}");
                return $"Unable to describe acc freq map: {ex.Message}";
            }
        }

        /// <summary>
        /// Construct the detection
        /// </summary>
        /// <param name="onAlert">delegated to abstract class</param>
        /// <param name="eventHandler">delegated to abstract class</param>
        public Detection_FileAccessPattern(Action<Alert> onAlert, WinEventHandler eventHandler, string dirName, int millisPerBatch,
            int millisPerCheck, int timeKeyLowerBound, int countTriggerBound, string nameOfTarget, string[] fileNames, EventID evid) : base(onAlert, eventHandler)
        {
            DirName = dirName;
            MillisPerBatch = millisPerBatch;
            MillisPerCheck = millisPerCheck;
            TimeKeyLowerBound = timeKeyLowerBound;
            CountTriggerBound = countTriggerBound;
            TargetName = nameOfTarget;
            FileNames = fileNames;
            Evid = evid;
            Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "Class", () => "Object initialized");
        }

        /// <summary>
        /// Start the detection.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the detection is already enabled</exception>
        public override void Start()
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "Start", () => "Starting detection...");

            // Don't start if already enabled
            if (Enabled)
            {
                throw new InvalidOperationException("Detection is already enabled");
            }

            Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "Start", () => "Initializing detection...");

            // If any of these fail, clean up as much as possible, and rethrow exception.
            try
            {
                InitialiseAccFreqMap();
                StartTimers();
                StartWatchers();
            }
            catch (Exception ex)
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "Start", () => "Caught exception: " + ex.Message);
                Stop();
                throw;
            }

            // Update enabled state here.
            Enabled = true;
            Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "Start", () => "Detection initialized.");
        }

        /// <summary>
        /// Initialize the access frequency map with each file name paired with a child dictionary of values (0, 0).
        /// </summary>
        private void InitialiseAccFreqMap()
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "InitialiseAccFreqMap", () => "Method called...");
            lock (AccFreqMap)
            {
                foreach (string fileName in FileNames)
                {
                    ConcurrentDictionary<int, int> countByTimeMap = new();
                    countByTimeMap.TryAdd(0, 0); // no Add method so can't initialize this inline :(
                    AccFreqMap.TryAdd(fileName, countByTimeMap);
                    Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "InitialiseAccFreqMap", () => $"TryAdd fileName = {fileName} set 0,0");
                }
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "InitialiseAccFreqMap", () => $"Initialized map with {AccFreqMap.Count} vals.");
            }
        }

        /// <summary>
        /// Start all of the timers required to run this detection
        /// </summary>
        private void StartTimers()
        {
            try
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "StartTimers", () => "Method called...");

                // Initialize AccFreqMapUpdateTask
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "StartTimers", () => "Initializing AccFreqMapUpdateTask...");
                AccFreqMapUpdateTimer = new Timer(
                    callback: o => HandleAccFreqMapUpdate(),
                    state: null,
                    dueTime: 0,
                    period: MillisPerBatch); // millis

                // Initialize MaliciousCheckerTask
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "StartTimers", () => "Initializing MaliciousCheckerTask...");
                MaliciousCheckerTimer = new Timer(
                    callback: o => HandleMaliciousChecker(),
                    state: null,
                    dueTime: 0,
                    period: MillisPerCheck); // millis

                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "StartTimers", () => "Initialized all timers.");
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
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MAPUPDATE, "HandleAccFreqMapUpdate", () => "Method called...");

                lock (AccFreqMap)
                {
                    foreach (string key in AccFreqMap.Keys)
                    {
                        ConcurrentDictionary<int, int> accFreq = AccFreqMap[key];
                        foreach (int timeKey in accFreq.Keys.ToArray().OrderDescending())
                        {
                            // If the time key is below the bound desired (timeKeyLowerBound), simply discard it, as it's no longer needed.
                            // Else, drop-down / age each batch, decrementing its ID and reinitializing ID=0 to a count value of 0.
                            if (timeKey < TimeKeyLowerBound)
                            {
                                // Try remove.
                                accFreq.TryRemove(timeKey, out int _);

                                // Completed!
                                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MAPUPDATE, "HandleAccFreqMapUpdate", () => $"TryRemove timeKey={timeKey}.");
                            }
                            else
                            {
                                // Drop-down
                                accFreq[timeKey - 1] = accFreq[timeKey];

                                // Reinitialize
                                if (timeKey == 0)
                                {
                                    accFreq[timeKey] = 0;
                                    Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MAPUPDATE, "HandleAccFreqMapUpdate", () => $"Reset timeKey={timeKey} to {accFreq[timeKey]}.");
                                }

                                // Completed!
                                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MAPUPDATE, "HandleAccFreqMapUpdate", () => $"Drop-down to timeKey={timeKey - 1}.");
                            }
                        }
                    }
                }

                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MAPUPDATE, "HandleAccFreqMapUpdate", () => "Method complete.");
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
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "StartWatchers", () => "Method called...");
                foreach (string fileName in FileNames)
                {
                    Watchers.AddLast(
                        FileUtils.Watch(DirName, fileName, wfe => HandleFileEvent(wfe))
                    );
                }
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "StartWatchers", () => "Method complete.");
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
            if (!Enabled)
            {
                Logger.WriteWarn("Detection-FileAccessPattern", "Detection is stopping without being fully enabled (unsafe state). Continuing anyways to cleanup.");
            }

            try
            {
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "Stop", () => "Stopping detection...");
                DisposeWatchers();
                DisposeTimers();
                Enabled = false;
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "Stop", () => "Stopped detection.");
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
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "DisposeWatchers", () => "Method called...");
                foreach (FileSystemWatcher watcher in Watchers)
                {
                    watcher.Dispose();
                }
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "DisposeWatchers", () => "Method complete.");
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
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "DisposeTimers", () => "Method called...");
                MaliciousCheckerTimer?.Dispose();
                AccFreqMapUpdateTimer?.Dispose();
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_GENERIC, "DisposeTimers", () => "Method complete.");
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
                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_HANDLE, "Handle", () => $"Method called... wfe={wfe}");

                if (wfe.Type == FileUtils.FileEventType.ERROR || wfe.FileName.Length == 0)
                {
                    Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_HANDLE, "Handle", () => $"WFE type is error, msg={wfe.Descr}");
                    return;
                }

                lock (AccFreqMap)
                {
                    ConcurrentDictionary<int, int> countByTime = AccFreqMap[wfe.FileName.ToLower()];
                    int cbt = countByTime[0] + 1;
                    countByTime[0] = cbt;
                    Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_HANDLE, "Handle", () => $"Method complete. (countByTime = {countByTime}, cbt = {cbt})");
                }

                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_HANDLE, "Handle", () => "Delegating malicious activity checking to HandleMaliciousChecker");
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
            Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MALCHECKER, "HandleMaliciousChecker", () => "Method called...");
            LinkedList<string> fileNamesWithWatchedEvent = new();

            try
            {
                lock (AccFreqMap)
                {
                    foreach (string fileName in AccFreqMap.Keys)
                    {
                        Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MALCHECKER, "HandleMaliciousChecker", () => "Checking key " + fileName);

                        int totalCount = 0;

                        ConcurrentDictionary<int, int> accFreq = AccFreqMap[fileName];
                        foreach (int timeKey in accFreq.Keys)
                        {
                            int count = accFreq[timeKey];
                            totalCount += count;
                            Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MALCHECKER, "HandleMaliciousChecker", () => $"timeKey={timeKey}, count={count}, total={totalCount}");
                        }

                        if (totalCount > 1)
                        {
                            Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MALCHECKER, "HandleMaliciousChecker", () => $"totalCount>1, so adding to watched event list");
                            fileNamesWithWatchedEvent.AddLast(fileName);
                        }
                    }

                    if (fileNamesWithWatchedEvent.Count >= CountTriggerBound)
                    {
                        Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MALCHECKER, "HandleMaliciousChecker", () => $"High number of watched events, triggering detection!");
                        string shortDesc = $"Possible use of {TargetName} detected on this system judgying by file access patterns. Trigger count is {CountTriggerBound}; matched {fileNamesWithWatchedEvent.Count} of {FileNames.Length} associated file names.";
                        string longDesc = $"Please see further details below.\n{DescribeAccFreqMap()}";
                        Alert dinfo = new(TargetAlertType, shortDesc, longDesc);
                        OnAlert(dinfo);
                        WriteEvent(dinfo);
                    }
                }

                Logger.WriteDebug(DebugCategory.DETECTIONS_FILEACCESSPATTERN_MALCHECKER, "HandleMaliciousChecker", () => "Method complete.");
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
                CategoryID catID = CategoryID.DETECTIONS;
                EventHandler.WriteEvent(alert.ToReadableString(), System.Diagnostics.EventLogEntryType.Warning, Evid, catID);
            }
            catch (Exception ex)
            {
                Logger.WriteErr("WriteEvent", $"Unable to write event: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
                // this method is not important so it will not rethrow ex.
            }
        }
    }
}
