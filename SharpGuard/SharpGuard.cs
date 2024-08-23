using System.Collections.Generic;

namespace SharpGuard
{
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

        private CLI GuardCLI { get; init; } = new();

        public SharpGuard()
        {
            Detections.AddLast(new Detection_Seatbelt_FileInfo(di => OnDetect(di)));
        }

        void Start()
        {
            StartDetections();
            GuardCLI.Initialize("SharpGuard v0.1");
        }

        void Stop()
        {
            StopDetections();
        }

        void StartDetections()
        {
            Logger.WriteDebug(DebugCategory.Detections, "StartDetections", () => "Starting detections...");
            foreach (var dec in Detections)
            {
                dec.Start();
            }
            Logger.WriteDebug(DebugCategory.Detections, "StartDetections", () => $"Started {Detections.Count} detections.");
        }

        void StopDetections()
        {
            Logger.WriteDebug(DebugCategory.Detections, "StopDetections", () => "Stopping detections...");
            foreach (var dec in Detections)
            {
                dec.Stop();
            }
            Logger.WriteDebug(DebugCategory.Detections, "StopDetections", () => $"Stopped {Detections.Count} detections.");
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "<Pending>")]
        void OnDetect(DetectionInfo dinfo)
        {
            Logger.WriteDebug(DebugCategory.Detections, "OnDetect", () => $"Detection received! Object: " + dinfo);
        }
    }
}
