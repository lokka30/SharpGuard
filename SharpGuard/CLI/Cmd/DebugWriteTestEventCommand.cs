using System;
using System.Linq;
using System.Runtime.Versioning;
using SharpGuard.Log;

namespace SharpGuard.CLI.Cmd
{
    /// <summary>
    /// This command aids in testing if the WinEventHandler class logic is working.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal class DebugWriteTestEventCommand : Command
    {
        private static readonly string name = "(Debugging) Write Test Event";
        private static readonly string description = "Writes a test event to the Windows event log.";
        private static readonly string[] aliases = { "debug-write-test-event", "dbg-write-test-event" };
        private static readonly string usage = aliases.First();
        private SharpGuard SG { get; init; }

        public DebugWriteTestEventCommand(SharpGuard sg) : base(name, description, aliases, usage)
        {
            SG = sg;
        }

        public override bool Execute(string[] args)
        {
            Logger.WriteInfo("DebugWriteTestEvent", "Writing test event...");
            SG.EventHandler.WriteEvent($"This\nis\na\ntest\nevent\nDateTime: {DateTime.Now}", System.Diagnostics.EventLogEntryType.Information, 0, 0);
            Logger.WriteInfo("DebugWriteTestEvent", "Completed.");
            return false;
        }
    }

}
