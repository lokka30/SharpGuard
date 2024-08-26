using System;

namespace SharpGuard
{
    internal abstract class Detection
    {
        public Detection(Action<DetectionInfo> onDetectHook, WinEventHandler eventHandler)
        {
            OnDetectHook = onDetectHook;
            EventHandler = eventHandler;
        }

        protected WinEventHandler EventHandler { get; init; }
        internal Action<DetectionInfo> OnDetectHook { get; init; }

        public abstract void Start(WinEventHandler eventHandler);

        public abstract void Stop();

        protected void OnDetect(DetectionInfo dinfo)
        {
            Logger.WriteDebug(DebugCategory.Detections, "Detection.OnDetect", () => "Abstract method called.");
            OnDetectHook.Invoke(dinfo);
        }
    }
}
