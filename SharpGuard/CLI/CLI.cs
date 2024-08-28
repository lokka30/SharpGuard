using SharpGuard.Log;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace SharpGuard.CLI.Cmd
{

    /// <summary>
    /// Houses most of the logic used in the SharpGuard CLI.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class CLI
    {
        /// <summary>
        /// Commands usable in the CLI.
        /// </summary>
        internal LinkedList<Command> Commands { get; init; } = new();

        /// <summary>
        /// Ref to SharpGuard obj
        /// </summary>
        private SharpGuard SG { get; init; }

        /// <summary>
        /// Construct the CLI with the provided SharpGuard object ref
        /// </summary>
        /// <param name="sg">Reference to SharpGuard object</param>
        public CLI(SharpGuard sg)
        {
            SG = sg;
            Commands.AddLast(new ExitCommand());
            Commands.AddLast(new HelpCommand(Commands));
            Commands.AddLast(new DebugWriteTestEventCommand(SG));
            Commands.AddLast(new DebugCategoryCommand());
            Console.CancelKeyPress += (_, ea) =>
            {
                ea.Cancel = true;
                Logger.WriteWarn("SharpGuard", "Received SIGINT/SIGTERM, stopping program...");
                sg.Stop();
            };
        }

        /// <summary>
        /// Initialize the CLI.
        /// </summary>
        /// <param name="appDetails">Any details to be displayed about the app</param>
        public void Initialize(string appDetails)
        {
            Logger.WriteInfo("Main Menu", $"Welcome to {appDetails}");
            while (true)
            {
                if (ProcessCommand(ReadCommandWithArgs()))
                {
                    break;
                }
            }
        }

        /// <summary>
        /// Read command from CLI.
        /// </summary>
        /// <returns>Command with arguments in single array</returns>
        private static string[] ReadCommandWithArgs()
        {
            Logger.WriteInfo("Main Menu", "Awaiting command... (use 'help' for help)");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" % ");
            Console.ForegroundColor = ConsoleColor.Blue;
            string cmd = Console.ReadLine() ?? "";
            Console.ForegroundColor = ConsoleColor.White;
            cmd = cmd.Trim();
            cmd = Regex.Replace(cmd, @"\s", " ");
            return cmd.Split(" ");
        }

        /// <summary>
        /// Process command with arguments.
        /// </summary>
        /// <param name="cmdWithArgs">Command with arguments in single array</param>
        /// <returns>whether the program should exit</returns>
        private bool ProcessCommand(string[] cmdWithArgs)
        {
            string cmd = cmdWithArgs[0].ToLower();

            if (cmd.Length == 0)
            {
                Logger.WriteErr("Main Menu", "Please enter a command. For help, type 'help'.");
                return false;
            }

            foreach (Command handler in Commands)
            {
                if (handler.Aliases.Contains(cmd))
                {
                    string[] args = cmdWithArgs.Skip(1).ToArray();
                    bool shouldExit = handler.Execute(args);
                    return shouldExit;
                }
            }

            Logger.WriteErr("Main Menu", "Unrecognised command, please try again. For help, type 'help'.");
            return false;
        }
    }

}
