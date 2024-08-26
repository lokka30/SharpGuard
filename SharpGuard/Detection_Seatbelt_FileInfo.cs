using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;

namespace SharpGuard
{
    [SupportedOSPlatform("windows")]
    internal class Detection_Seatbelt_FileInfo : Detection
    {
        public static readonly string[] fileNames = {
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
        }; // file names of interest inside 'C:\Windows\System32' or it's subdirectories. All must be lowercase!

        public static readonly int millisPerBatch = 10_000; // time between batches being separated, milliseconds
        public static readonly int millisPerCheck = 05_000; // time between scheduled checks, milliseconds
        public static readonly int timeKeyLowerBound = -2; // lower bound for the time key; time keys lower than this are discarded
        public static readonly int countTriggerBound = 4; // count # required to trigger alert

        private bool Enabled { get; set; } = false; // This keeps track if the detection has attempted to have been started twice in a row

        private LinkedList<FileSystemWatcher> Watchers { get; init; } = new();

        /*
         * 30 second batches of access frequencies.
         * 
         * Format: Dictionary<string FileName, Dictionary<int TimeKey, int AccessCount>
         */
        private ConcurrentDictionary<string, ConcurrentDictionary<int, int>> AccFreqMap { get; init; } = new();

        // every X seconds, remove any old time key entries, and make each existing time key entry older.
        private Timer? AccFreqMapUpdateTask { get; set; } = null;

        // every X seconds, check all keys to see if all counts are suspicious
        private Timer? MaliciousCheckerTask { get; set; } = null;

        public string DescribeAccFreqMap()
        {
            try
            {
                lock (AccFreqMap)
                {
                    StringBuilder sb = new("Access Frequency Map Overview:\n");
                    sb.Append(new string('-', 30));
                    sb.Append("\nFormat: File Name - Batch ID - Batch age (mins) - Count\n");

                    foreach (var fileName in AccFreqMap.Keys)
                    {
                        var batchAgeToCount = AccFreqMap[fileName];
                        foreach (var batchAgeId in batchAgeToCount.Keys.Order())
                        {
                            var batchAgeMins = Math.Round(batchAgeId == 0 ? 0f : batchAgeId * -millisPerBatch / (60_000), 2);
                            var batchCount = batchAgeToCount[batchAgeId];

                            /*
                            sb.Append(" -> ");
                            sb.Append(fileName);
                            sb.Append(": ID#");
                            sb.Append(batchAgeId);
                            sb.Append(", ");
                            sb.Append(batchAgeMins); // batch age in minutes
                            sb.Append("mins, ");
                            sb.Append(batchCount); // count
                            sb.Append(" matches.\n");
                            */

                            sb.Append(String.Format("| {0,-24} | #{1,-4} | {2,-4}m ago | {3,-4} hits |", fileName, batchAgeId, batchAgeMins, batchCount));
                        }
                    }

                    return sb.ToString();
                }
            }
            catch (Exception ex)
            {
                Logger.WriteErr("Detection_Seatbelt_FileInfo", $"Caught exception: {ex.Message}; Stack Trace:\n{ex.StackTrace ?? "N/A"}");
                return $"Unable to describe acc freq map: {ex.Message}";
            }
        }

        public Detection_Seatbelt_FileInfo(Action<DetectionInfo> onDetectHook, WinEventHandler eventHandler) : base(onDetectHook, eventHandler)
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Class", () => "Object initialized");
        }

        public override void Start(WinEventHandler eventHandler)
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Start", () => "Starting detection...");

            if (Enabled)
            {
                throw new InvalidOperationException("Detection is already enabled");
            }

            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Start", () => "Initializing detection...");

            try
            {
                InitialiseAccFreqMap();
                StartTimers();
                StartWatchers();
            }
            catch (Exception ex)
            {
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Start", () => "Caught exception: " + ex.Message);
                Stop();
                throw;
            }

            Enabled = true;
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Start", () => "Detection initialized.");
        }

        private void InitialiseAccFreqMap()
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "InitialiseAccFreqMap", () => "Method called...");
            lock (AccFreqMap)
            {
                foreach (var fileName in fileNames)
                {
                    var countByTimeMap = new ConcurrentDictionary<int, int>();
                    countByTimeMap.TryAdd(0, 0);
                    AccFreqMap.TryAdd(fileName, countByTimeMap);
                    Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "InitialiseAccFreqMap", () => "TryAdd fileName = " + fileName);
                }
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "InitialiseAccFreqMap", () => $"Initialized map with {AccFreqMap.Count} vals.");
            }
        }

        private void StartTimers()
        {
            try
            {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartTimers", () => "Method called...");

            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartTimers", () => "Initializing AccFreqMapUpdateTask...");
            AccFreqMapUpdateTask = new Timer(
                callback: o => HandleAccFreqMapUpdate(),
                state: null,
                dueTime: 0,
                period: millisPerBatch); // millis

            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartTimers", () => "Initializing MaliciousCheckerTask...");
            MaliciousCheckerTask = new Timer(
                callback: o => HandleMaliciousChecker(),
                state: null,
                dueTime: 0,
                period: millisPerCheck); // millis

            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartTimers", () => "Initialized all timers.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("StartTimers", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
            }
            
        }

        private void HandleAccFreqMapUpdate()
        {
            
            try
            {
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleAccFreqMapUpdate", () => "Method called...");

            lock (AccFreqMap)
            {
                foreach (var key in AccFreqMap.Keys)
                {
                    var accFreq = AccFreqMap[key];
                    foreach (var timeKey in accFreq.Keys.ToArray().OrderDescending())
                    {
                        if (timeKey < timeKeyLowerBound)
                        {
                            accFreq.TryRemove(timeKey, out int _);
                            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleAccFreqMapUpdate", () => "TryRemove timeKey=" + timeKey);
                        }
                        else
                        {
                            accFreq[timeKey - 1] = accFreq[timeKey];
                            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleAccFreqMapUpdate", () => "Drop-down to timeKey=" + (timeKey - 1));
                        }
                    }
                }
            }

            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleAccFreqMapUpdate", () => "Method complete.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("HandleAccFreqMapUpdate", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
            }
        }

        private void StartWatchers()
        {
            try
            {
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartWatchers", () => "Method called...");
                foreach (var fileName in fileNames)
                {
                    Watchers.AddLast(
                        FileUtils.Watch(@"C:\Windows\System32", fileName, wfe => Handle(wfe))
                    );
                }
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartWatchers", () => "Method complete.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("StartWatchers", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
            }
        }

        // Intended behaviour here is that the 'Enabled' state is ignored, in case an exception happens and SharpGuard wants to make
        // sure everything has been cleaned up using the Stop method.
        public override void Stop()
        {
            try
            {
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Stop", () => "Stopping detection...");
                DisposeWatchers();
                DisposeTasks();
                Enabled = false;
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Stop", () => "Stopped detection.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("Stop", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
            }
        }

        private void DisposeWatchers()
        {
            try
            {
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "DisposeWatchers", () => "Method called...");
                foreach (var watcher in Watchers)
                {
                    watcher.Dispose();
                }
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "DisposeWatchers", () => "Method complete.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("DisposeWatchers", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
            }

            
        }

        private void DisposeTasks()
        {
            try
            {
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "DisposeTasks", () => "Method called...");
                MaliciousCheckerTask?.Dispose();
                AccFreqMapUpdateTask?.Dispose();
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "DisposeTasks", () => "Method complete.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("Handle", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
            }
        }

        private void Handle(FileUtils.WatchedFileEvent wfe)
        {
            try
            {
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Handle", () => "Method called... wfe=" + wfe);
            if (wfe.Type == FileUtils.FileEventType.ERROR)
            {
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Handle", () => "WFE type is error, msg=" + wfe.Descr);
                return;
            }

            lock (AccFreqMap)
            {
                var countByTime = AccFreqMap[wfe.FileName.ToLower()];
                var cbt = countByTime[0] + 1;
                countByTime[0] = cbt;
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Handle", () => $"Method complete. (countByTime = {countByTime}, cbt = {cbt})");
            }
            }
            catch (Exception ex)
            {
                Logger.WriteErr("Handle", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
            }
        }

        private void HandleMaliciousChecker()
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleMaliciousChecker", () => "Method called...");
            var fileNamesWithWatchedEvent = new LinkedList<string>();

            try
            {
                lock (AccFreqMap)
                {
                    foreach (var fileName in AccFreqMap.Keys)
                    {
                        Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleMaliciousChecker", () => "Checking key " + fileName);

                        var totalCount = 0;

                        var accFreq = AccFreqMap[fileName];
                        foreach (var timeKey in accFreq.Keys)
                        {
                            var count = accFreq[timeKey];
                            totalCount += count;
                            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleMaliciousChecker", () => $"timeKey={timeKey}, count={count}, total={totalCount}");
                        }

                        if (totalCount > 1)
                        {
                            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleMaliciousChecker", () => $"totalCount>1, so adding to watched event list");
                            fileNamesWithWatchedEvent.AddLast(fileName);
                        }
                    }
                }

                lock (AccFreqMap)
                {
                    if (fileNamesWithWatchedEvent.Count >= countTriggerBound)
                    {
                        Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleMaliciousChecker", () => $"High number of watched events, triggering detection!");
                        string shortDesc = $"Possible use of Seatbelt detected on this system judgying by file access patterns. Trigger count is {countTriggerBound}; matched {fileNamesWithWatchedEvent.Count} of {fileNames.Length} associated file names).";
                        string longDesc = DescribeAccFreqMap();
                        DetectionInfo dinfo = new(DetectionCategory.SEATBELT_FILEINFO, shortDesc, longDesc);
                        OnDetect(dinfo);
                        WriteEvent(dinfo);
                    }
                }

                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleMaliciousChecker", () => "Method complete.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("HandleMaliciousChecker", $"Caught exception: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
            }
        }

        private void WriteEvent(DetectionInfo dinfo)
        {
            try
            {
                var eventID = EventID.DETECTION_SEATBELT_FILEINFO;
                var catID = CategoryID.DETECTIONS;
                EventHandler.WriteEvent(dinfo.ToReadableString(), System.Diagnostics.EventLogEntryType.Warning, eventID, catID);
            }
            catch (Exception ex)
            {
                Logger.WriteErr("WriteEvent", $"Unable to write event: {ex.Message}; Stack trace: ${ex.StackTrace ?? "N/A"}");
            }
        }
    }
}
