using SharpGuard.Log;
using System;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace SharpGuard.Event
{

    /// <summary>
    /// Event IDs used by SharpGuard for Windows Event Logs
    /// </summary>
    public enum EventID : int
    {
        GENERIC = 0,
        DETECTION_SEATBELT_FILEINFO = 1,
    }

    /// <summary>
    /// Category IDs used by SharpGuard for Windows Event Logs
    /// </summary>
    public enum CategoryID : short
    {
        GENERIC = 0,
        DETECTIONS = 1,
    }

    /// <summary>
    /// Contains various logic to handle Windows Event Logs
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class WinEventHandler
    {
        /// <summary>
        /// Access to Windows Event Log
        /// </summary>
        private readonly EventLog eventLog = new();

        /// <summary>
        /// Whether the WinEventHandler has been initialized.
        /// </summary>
        private bool IsInitialized { get; set; } = false;

        /// <summary>
        /// Initialize the WinEventHandler. Only call once.
        /// </summary>
        public void Initialize()
        {
            // If already initialized, don't try to re-initialize.
            if (IsInitialized)
            {
                throw new InvalidOperationException("Already initialized");
            }

            // Create event source if not exists
            if (!EventLog.SourceExists("SharpGuard"))
            {
                EventLog.CreateEventSource("SharpGuard", "Application");
            }

            // Update relevant properties of the event log.
            eventLog.Source = "SharpGuard";

            // Conclude by updating initialized state.
            IsInitialized = true;
        }

        /// <summary>
        /// Write an event to the event log with the given data parameters.
        /// </summary>
        /// <param name="text">Description of the event</param>
        /// <param name="type">Type of event</param>
        /// <param name="eventID">Event ID to use</param>
        /// <param name="catID">Category ID to use</param>
        public void WriteEvent(string text, EventLogEntryType type, EventID eventID, CategoryID catID)
        {
            try
            {
                eventLog.WriteEntry(text, type, (int)eventID, (short)catID);
            }
            catch (Exception ex)
            {
                // If an exception happens here, it's not crucial to program operation, just log it and move on.
                Logger.WriteErr("WriteEvent", $"Caught exception {ex.Message}; Stack Trace: {ex.StackTrace ?? "N/A"}");
            }
        }
    }

}
