using System;

namespace SharpGuard
{
    internal abstract class Detection
    {
        public Detection(Action<DetectionInfo> onDetectHook) => OnDetectHook = onDetectHook;

        internal Action<DetectionInfo> OnDetectHook { get; init; }

        public abstract void Start();

        public abstract void Stop();

        protected void OnDetect(DetectionInfo dinfo)
        {
            Logger.WriteDebug(DebugCategory.Detections, "Detection.OnDetect", () => "Abstract method called, object: " + dinfo);
            OnDetectHook.Invoke(dinfo);
        }
    }
}
