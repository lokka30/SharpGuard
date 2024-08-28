using System.Linq;
using System.Runtime.Versioning;
using SharpGuard.Log;

namespace SharpGuard.CLI.Cmd
{
    /// <summary>
    /// This command exits the program.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal class ExitCommand : Command
    {
        private static readonly string name = "Exit Program";
        private static readonly string description = "Exits the program.";
        private static readonly string[] aliases = { "exit", "ex", "quit", "q" };
        private static readonly string usage = aliases.First();

        public ExitCommand() : base(name, description, aliases, usage)
        {
        }

        public override bool Execute(string[] args)
        {
            Logger.WriteInfo("Exit", "Thank you and goodbye");
            return true;
        }
    }

}
