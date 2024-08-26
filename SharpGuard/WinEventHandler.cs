using System;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace SharpGuard
{
    public enum EventID : int
    {
        GENERIC = 0,
        DETECTION_SEATBELT_FILEINFO = 1,
    }

    public enum CategoryID : short
    {
        GENERIC = 0,
        DETECTIONS = 1,
    }

    // TODO: Add debug logging to file.
    [SupportedOSPlatform("windows")]
    internal class WinEventHandler
    {
        private readonly EventLog eventLog = new();

        public void Initialize()
        {
            if (!EventLog.SourceExists("SharpGuard"))
            {
                // Create event source
                EventLog.CreateEventSource("SharpGuard", "Application");
            }

            eventLog.Source = "SharpGuard";
        }

        public void WriteEvent(string text, EventLogEntryType type, EventID eventID, CategoryID catID)
        {
            try
            {
                eventLog.WriteEntry(text, type, (int)eventID, (short)catID);
            }
            catch (Exception ex)
            {
                Logger.WriteErr("WriteEvent", $"Caught exception {ex.Message}; Stack Trace: {ex.StackTrace ?? "N/A"}");
            }
        }
    }

}
