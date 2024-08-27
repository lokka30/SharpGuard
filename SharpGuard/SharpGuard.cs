using System;
using System.Collections.Generic;
using System.Runtime.Versioning;

namespace SharpGuard
{
    [SupportedOSPlatform("windows")]
    internal class SharpGuard
    {

        static void Main()
        {
            SharpGuard instance = new();
            instance.Start();
            instance.Stop();
        }

        private readonly LinkedList<Detection> detections = new();
        private LinkedList<Detection> Detections => detections;

        public WinEventHandler EventHandler { get; init; } = new();
        public CLI GuardCLI { get; init; }

        public SharpGuard()
        {
            GuardCLI = new(this);
            Detections.AddLast(new Detection_Seatbelt_FileInfo(di => OnDetect(di), EventHandler));
        }

        void Start()
        {
            EventHandler.Initialize();
            StartDetections();
            GuardCLI.Initialize("SharpGuard v0.1");
        }

        public void Stop()
        {
            StopDetections();
            Environment.Exit(0);
        }

        void StartDetections()
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_GENERIC, "StartDetections", () => "Starting detections...");
            foreach (var dec in Detections)
            {
                dec.Start(EventHandler);
            }
            Logger.WriteDebug(DebugCategory.DETECTIONS_GENERIC, "StartDetections", () => $"Started {Detections.Count} detections.");
        }

        void StopDetections()
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_GENERIC, "StopDetections", () => "Stopping detections...");
            foreach (var dec in Detections)
            {
                dec.Stop();
            }
            Logger.WriteDebug(DebugCategory.DETECTIONS_GENERIC, "StopDetections", () => $"Stopped {Detections.Count} detections.");
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "<Pending>")]
        void OnDetect(DetectionInfo dinfo)
        {
            Logger.WriteWarn("OnDetect", $"Detection received! Details:\n{dinfo.ToReadableString()}");
        }
    }
}
