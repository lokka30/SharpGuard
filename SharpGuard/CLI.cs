using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace SharpGuard
{
    [SupportedOSPlatform("windows")]
    public abstract class Command
    {
        public string Name { get; init; }
        public string Description { get; init; }
        public string[] Aliases { get; init; }
        public string Usage { get; init; }

        public Command(string name, string description, string[] aliases, string usage)
        {
            Name = name;
            Description = description;
            Aliases = aliases;
            Usage = usage;
        }

        // Execute command with provided args
        // If the command should cause the CLI to exit, return true.
        public abstract bool Execute(string[] args);
    }

    [SupportedOSPlatform("windows")]
    class HelpCommand : Command
    {
        private static readonly string name = "Help Menu";
        private static readonly string description = "Show help for available commands.";
        private static readonly string[] aliases = { "help", "h", "man", "manual" };
        private static readonly string usage = aliases.First();

        private LinkedList<Command> CommandHandlers { get; init; }

        public HelpCommand(LinkedList<Command> commandHandlers) : base(name, description, aliases, usage)
        {
            CommandHandlers = commandHandlers;
        }

        public override bool Execute(string[] args)
        {
            lock (Logger.locker)
            {
                // header...
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("+---------------+ ");
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write("CLI Help Menu");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(" +---------------+");
                Console.WriteLine();

                // show help for each cmd...
                foreach (var handler in CommandHandlers)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write(" \xbb ");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write(handler.Name);
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine(":");

                    Console.Write("    :: Description: ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(handler.Description);

                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("    :: Aliases: ");
                    Console.ForegroundColor = ConsoleColor.White;
                    foreach (var alias in handler.Aliases)
                    {
                        Console.Write(alias);
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.Write("; ");
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                    Console.WriteLine();

                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.Write("    :: Usage: ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(handler.Usage);

                    Console.WriteLine();
                }

                // footer...
                // let's pretend this is paginated for now - also an excuse
                // to write something different in the footer
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("+----------------+ ");
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write("Page 1 of 1");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(" +----------------+");
                Console.ForegroundColor = ConsoleColor.White;
            }

            // ret false - not exiting CLI
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    class ExitCommand : Command
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

    [SupportedOSPlatform("windows")]
    class DebugWriteTestEventCommand : Command
    {
        private static readonly string name = "(Debugging) Write Test Event";
        private static readonly string description = "Writes a test event to the Windows event log.";
        private static readonly string[] aliases = { "debug-write-test-event" };
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

    [SupportedOSPlatform("windows")]
    class CLI
    {
        public LinkedList<Command> CommandHandlers { get; init; } = new();
        public bool IsVerbose { get; set; } = false;
        private SharpGuard SG { get; init; }

        public CLI(SharpGuard sg)
        {
            SG = sg;
            CommandHandlers.AddLast(new ExitCommand());
            CommandHandlers.AddLast(new HelpCommand(CommandHandlers));
            CommandHandlers.AddLast(new DebugWriteTestEventCommand(SG));
        }

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

        private static string[] ReadCommandWithArgs()
        {
            Logger.WriteInfo("Main Menu", "Awaiting command... (use 'h' for help)");
            lock (Logger.locker)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" % ");
                Console.ForegroundColor = ConsoleColor.Blue;
            }
            var cmd = Console.ReadLine() ?? "";
            Console.ForegroundColor = ConsoleColor.White;
            cmd = cmd.Trim();
            cmd = Regex.Replace(cmd, @"\s", " ");
            return cmd.Split(" ");
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0051:Remove unused private members", Justification = "<Pending>")]
        private static void Pause()
        {
            Logger.WriteInfo("!", "Press [ENTER] to continue...", false);
            Console.ReadLine();
        }

        // Process command via given string
        // Returns whether the program should exit
        private bool ProcessCommand(string[] cmdWithArgs)
        {
            var cmd = cmdWithArgs[0].ToLower();

            foreach (var handler in CommandHandlers)
            {
                if (handler.Aliases.Contains(cmd))
                {
                    var args = cmdWithArgs.Skip(1).ToArray();
                    var shouldExit = handler.Execute(args);
                    /*
                    if (!shouldExit)
                    {
                        Pause();
                    }
                    */
                    Console.Out.Flush();
                    return shouldExit;
                }
            }

            Logger.WriteInfo("Main Menu", "Unrecognised command, please try again. For help, type 'help'.");
            return false;
        }
    }

    public enum DebugCategory
    {
        FileWatching,
        Detections,
        Detections_Seatbelt_FileInfo,
        Uncategorised
    }

}
