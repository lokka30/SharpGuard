using SharpGuard.CLI;
using SharpGuard.Detection;
using SharpGuard.Detection.Seatbelt;
using SharpGuard.Event;
using SharpGuard.Log;
using System;
using System.Collections.Generic;
using System.Runtime.Versioning;

namespace SharpGuard
{
    /// <summary>
    /// Program main class
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class SharpGuard
    {

        /// <summary>
        /// Program main function
        /// </summary>
        static void Main()
        {
            SharpGuard instance = new();
            instance.Start();
            instance.Stop();
        }

        /// <summary>
        /// Detections currently usable. Note that they may be stopped/disabled or enabled/started
        /// </summary>
        private LinkedList<Detection.Detection> Detections { get; init; } = new();

        /// <summary>
        /// Windows event handler
        /// </summary>
        public WinEventHandler EventHandler { get; init; } = new();

        /// <summary>
        /// CLI handler
        /// </summary>
        public GuardCLI GuardCLI { get; init; } // Initialized in this constructor.

        /// <summary>
        /// Construct SharpGuard instance.
        /// Only designed to have one active at a time, but may get away with multiple.
        /// </summary>
        public SharpGuard()
        {
            GuardCLI = new(this);
            Detections.AddLast(new Detection_Seatbelt_FileInfo(di => HandleAlert(di), EventHandler));
            Detections.AddLast(new Detection_Seatbelt_Lolbas(di => HandleAlert(di), EventHandler));
        }

        /// <summary>
        /// Start SharpGuard.
        /// </summary>
        void Start()
        {
            EventHandler.Initialize();
            StartDetections();
            GuardCLI.Initialize("SharpGuard v0.1");
        }

        /// <summary>
        /// Stop SharpGuard.
        /// </summary>
        public void Stop()
        {
            StopDetections();
            Environment.Exit(0);
        }

        /// <summary>
        /// Start SharpGuard's detections.
        /// Requires the Detections collection to have been populated already.
        /// </summary>
        void StartDetections()
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_GENERIC, "StartDetections", () => "Starting detections...");
            foreach (var dec in Detections)
            {
                dec.Start();
            }
            Logger.WriteDebug(DebugCategory.DETECTIONS_GENERIC, "StartDetections", () => $"Started {Detections.Count} detections.");
        }

        /// <summary>
        /// Stop SharpGuard's detections.
        /// </summary>
        void StopDetections()
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_GENERIC, "StopDetections", () => "Stopping detections...");
            foreach (var dec in Detections)
            {
                dec.Stop();
            }
            Logger.WriteDebug(DebugCategory.DETECTIONS_GENERIC, "StopDetections", () => $"Stopped {Detections.Count} detections.");
        }

        /// <summary>
        /// This function is called whenever an alert is raised.
        /// </summary>
        /// <param name="alert"></param>
        private static void HandleAlert(Alert alert)
        {
            Logger.WriteWarn("OnDetect", $"Detection received! Details:\n{alert.ToReadableString()}");
        }
    }
}
