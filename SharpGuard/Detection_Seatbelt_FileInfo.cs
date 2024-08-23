using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace SharpGuard
{
    internal class Detection_Seatbelt_FileInfo : Detection
    {
        // const int MILLIS_PER_BATCH = 2_000; // TESTING ONLY
        const int MILLIS_PER_BATCH = 30_000;
        // const int MILLIS_PER_CHECK = 1_000; // TESTING ONLY
        const int MILLIS_PER_CHECK = 5_000;
        const int TIME_KEY_LIMIT = -6;
        const int TRIGGER_COUNT = 1; // TESTING ONLY
        // const int TRIGGER_COUNT = 1; // 10 to 14 recommended

        public string[] FileNames { get; } = {
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

        private LinkedList<FileSystemWatcher> Watchers { get; init; } = new();

        /*
         * 30 second batches of access frequencies.
         * 
         * Format: Dictionary<string FileName, Dictionary<int TimeKey, int AccessCount>
         */
        private ConcurrentDictionary<string, ConcurrentDictionary<int, int>> AccFreqMap { get; init; } = new();

        // every 30 seconds, remove any old time key entries, and make each existing time key entry older.
        private Timer? AccFreqMapUpdateTask { get; set; } = null;

        // every 5 seconds, check all keys to see if all counts are suspicious
        private Timer? MaliciousCheckerTask { get; set; } = null;

        public Detection_Seatbelt_FileInfo(Action<DetectionInfo> onDetectHook) : base(onDetectHook)
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Class", () => "Object initialized");
        }

        public override void Start()
        {
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

            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Start", () => "Detection initialized.");
        }

        private void InitialiseAccFreqMap()
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "InitialiseAccFreqMap", () => "Method called...");
            lock(AccFreqMap)
            {
                foreach (var fileName in FileNames)
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
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartTimers", () => "Method called...");

            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartTimers", () => "Initializing AccFreqMapUpdateTask...");
            AccFreqMapUpdateTask = new Timer(
                callback: o => HandleAccFreqMapUpdate(),
                state: null,
                dueTime: 0,
                period: MILLIS_PER_BATCH); // millis

            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartTimers", () => "Initializing MaliciousCheckerTask...");
            MaliciousCheckerTask = new Timer(
                callback: o => HandleMaliciousChecker(),
                state: null,
                dueTime: 0,
                period: MILLIS_PER_CHECK); // millis

            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartTimers", () => "Initialized all timers.");
        }

        private void HandleAccFreqMapUpdate()
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleAccFreqMapUpdate", () => "Method called...");

            lock(AccFreqMap)
            {
                foreach (var key in AccFreqMap.Keys)
                {
                    var accFreq = AccFreqMap[key];
                    foreach (var timeKey in accFreq.Keys.ToArray().OrderDescending())
                    {
                        if (timeKey < TIME_KEY_LIMIT)
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

        private void StartWatchers()
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartWatchers", () => "Method called...");
            foreach (var fileName in FileNames)
            {
                Watchers.AddLast(
                    FileUtils.Watch(@"C:\Windows\System32", fileName, wfe => Handle(wfe))
                );
            }
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "StartWatchers", () => "Method complete.");
        }

        public override void Stop()
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Stop", () => "Stopping detection...");
            DisposeWatchers();
            DisposeTasks();
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Stop", () => "Stopped detection.");
        }

        private void DisposeWatchers()
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "DisposeWatchers", () => "Method called...");
            foreach (var watcher in Watchers)
            {
                watcher.Dispose();
            }
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "DisposeWatchers", () => "Method complete.");
        }

        private void DisposeTasks()
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "DisposeTasks", () => "Method called...");
            MaliciousCheckerTask?.Dispose();
            AccFreqMapUpdateTask?.Dispose();
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "DisposeTasks", () => "Method complete.");
        }

        private void Handle(FileUtils.WatchedFileEvent wfe)
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Handle", () => "Method called... wfe=" + wfe);
            if (wfe.Type == FileUtils.FileEventType.ERROR)
            {
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Handle", () => "WFE type is error, msg=" + wfe.Descr);
                return;
            }

            lock(AccFreqMap)
            {
                var countByTime = AccFreqMap[wfe.FileName];
                var cbt = countByTime[0] + 1;
                countByTime[0] = cbt;
                Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "Handle", () => $"Method complete. (countByTime = {countByTime}, cbt = {cbt})");
            }
        }

        private void HandleMaliciousChecker()
        {
            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleMaliciousChecker", () => "Method called...");
            var fileNamesWithWatchedEvent = new LinkedList<string>();

            lock(AccFreqMap)
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

            lock(AccFreqMap)
            {
                if (fileNamesWithWatchedEvent.Count >= TRIGGER_COUNT)
                {
                    Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleMaliciousChecker", () => $"High number of watched events, triggering detection!");
                    OnDetect(new DetectionInfo(DetectionCategory.SEATBELT_FILEINFO, "tbd", AccFreqMap.ToString() ?? "N/A"));
                }
            }

            Logger.WriteDebug(DebugCategory.Detections_Seatbelt_FileInfo, "HandleMaliciousChecker", () => "Method complete.");
        }
    }
}
