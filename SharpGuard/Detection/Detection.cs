using System;
using SharpGuard.Event;
using SharpGuard.Log;

namespace SharpGuard.Detection
{

    /// <summary>
    /// Represents a detection that can monitor for activity to generate Alerts.
    /// </summary>
    public abstract class Detection
    {

        /// <summary>
        /// Constructs a Detection (abstract)
        /// </summary>
        /// <param name="alertHandler">Callback to handle alerts</param>
        /// <param name="eventHandler">Reference to event handler to write events for alerts</param>
        public Detection(Action<Alert> alertHandler, WinEventHandler eventHandler)
        {
            AlertHandler = alertHandler;
            EventHandler = eventHandler;
        }

        /// <summary>
        /// Reference to event handler to write events for alerts.
        /// </summary>
        protected WinEventHandler EventHandler { get; init; }

        /// <summary>
        /// Callback to handle alerts from this detection.
        /// </summary>
        internal Action<Alert> AlertHandler { get; init; }

        /// <summary>
        /// Enabled state
        /// </summary>
        protected bool Enabled { get; set; } = false;

        /// <summary>
        /// Starts the detection.
        /// </summary>
        public abstract void Start();

        /// <summary>
        /// Stops the detection. Cleanup.
        /// </summary>
        public abstract void Stop();

        /// <summary>
        /// Standard logic to handle alerts.
        /// </summary>
        /// <param name="alert">Reference to alert</param>
        protected void OnAlert(Alert alert)
        {
            Logger.WriteDebug(DebugCategory.DETECTIONS_GENERIC, "Detection.OnAlert", () => "Abstract method called.");
            AlertHandler.Invoke(alert);
        }
    }
}
