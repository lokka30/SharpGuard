using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using SharpGuard.Detection;
using SharpGuard.Detection.Seatbelt;
using SharpGuard.Event;
using SharpGuard.Log;

namespace SharpGuard
{
    [SupportedOSPlatform("windows")]
    public class SharpGuard
    {

        static void Main()
        {
            SharpGuard instance = new();
            instance.Start();
            instance.Stop();
        }

        private readonly LinkedList<Detection.Detection> detections = new();
        private LinkedList<Detection.Detection> Detections => detections;

        public WinEventHandler EventHandler { get; init; } = new();
        public SharpGuard.CLI.Cmd.CLI GuardCLI { get; init; }

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
                dec.Start();
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
        void OnDetect(Alert dinfo)
        {
            Logger.WriteWarn("OnDetect", $"Detection received! Details:\n{dinfo.ToReadableString()}");
        }
    }
}
