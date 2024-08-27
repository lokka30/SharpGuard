using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
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
    class DebugCategoryCommand : Command
    {
        private static readonly string name = "Debug Category Management";
        private static readonly string description = "Check or manage enabled debug categories to be logged.";
        private static readonly string[] aliases = { "debug-category" };
        private static readonly string usage = $"{aliases.First()} <add / rm / ls>";

        public DebugCategoryCommand() : base(name, description, aliases, usage)
        {
        }

        public override bool Execute(string[] args)
        {
            if (args.Length < 1)
            {
                Logger.WriteErr("Debugging", $"No subcommand specified. Usage: '{usage}'");
                return false;
            }

            switch (args[0].ToUpper())
            {
                case "ADD":
                    if (args.Length != 2)
                    {
                        Logger.WriteErr("Debugging", $"Invalid number of arguments. Usage: '{aliases.First()} add <category>'.");
                        break;
                    }

                    string catName_Add = args[1].ToUpper();

                    if(catName_Add == "*")
                    {
                        Logger.WriteInfo("Debugging", "Enabling all debug cateogries...");

                        try
                        {
                            foreach (int cat in Enum.GetValues(typeof(DebugCategory)))
                            {
                                Logger.EnabledDebugCategories.AddOrUpdate((DebugCategory)cat, true, (k, v) => true);
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteErr("Debugging", $"Caught exception:\nMessage: {ex.Message};\nStack Trace: {ex.StackTrace};");
                            break;
                        }

                        Logger.WriteInfo("Debugging", "Success.");
                        break;
                    }

                    DebugCategory cat_Add;

                    try
                    {
                        cat_Add = (DebugCategory)Enum.Parse(typeof(DebugCategory), catName_Add);
                    }
                    catch (Exception)
                    {
                        Logger.WriteErr("Debugging", $"Unable to parse debug category '{catName_Add}'. To list available values, use the 'ls' subcommand.");
                        break;
                    }

                    if (Logger.EnabledDebugCategories.GetOrAdd(cat_Add, false))
                    {
                        Logger.WriteWarn("Debugging", $"Category '{catName_Add}' is already enabled.");
                        break;
                    }

                    try
                    {
                        Logger.WriteInfo("Debugging", $"Enabling debug logging for category '{catName_Add}'...");
                        Logger.EnabledDebugCategories.AddOrUpdate(cat_Add, true, (_, _) => true);
                        Logger.WriteInfo("Debugging", $"Success.");
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteErr("Debugging", $"Caught exception;\nMessage: {ex.Message};\nStack Trace: {ex.StackTrace}");
                        break;
                    }

                    break;
                case "RM":
                case "DEL":
                case "REMOVE":
                case "DELETE":
                    if (args.Length != 2)
                    {
                        Logger.WriteErr("Debugging", $"Invalid number of arguments. Usage: '{aliases.First()} rm <category>'.");
                        break;
                    }

                    string catName_Rm = args[1].ToUpper();

                    if (catName_Rm == "*")
                    {
                        Logger.WriteInfo("Debugging", "Disabling all debug cateogries...");

                        try
                        {
                            foreach (int cat in Enum.GetValues(typeof(DebugCategory)))
                            {
                                Logger.EnabledDebugCategories.AddOrUpdate((DebugCategory)cat, false, (k, v) => false);
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.WriteErr("Debugging", $"Caught exception:\nMessage: {ex.Message};\nStack Trace: {ex.StackTrace};");
                            break;
                        }

                        Logger.WriteInfo("Debugging", "Success.");
                        break;
                    }

                    DebugCategory cat_Rm;

                    try
                    {
                        cat_Rm = (DebugCategory)Enum.Parse(typeof(DebugCategory), catName_Rm);
                    }
                    catch (Exception)
                    {
                        Logger.WriteErr("Debugging", $"Unable to parse debug category '{catName_Rm}'. To list available values, use the 'ls' subcommand.");
                        break;
                    }

                    if (!Logger.EnabledDebugCategories.GetValueOrDefault(cat_Rm, false))
                    {
                        Logger.WriteWarn("Debugging", $"Category '{catName_Rm}' is already disabled.");
                        break;
                    }

                    try
                    {
                        Logger.WriteInfo("Debugging", $"Disabling debug logging for category '{catName_Rm}'...");
                        Logger.EnabledDebugCategories.Remove(cat_Rm, out _);
                        Logger.WriteInfo("Debugging", $"Success.");
                    }
                    catch (Exception ex)
                    {
                        Logger.WriteErr("Debugging", $"Caught exception;\nMessage: {ex.Message};\nStack Trace: {ex.StackTrace}");
                        break;
                    }

                    break;
                case "LS":
                case "LIST":
                    if (args.Length != 1)
                    {
                        Logger.WriteErr("Debugging", $"Invalid number of arguments. Usage: '{aliases.First()} ls'.");
                        break;
                    }

                    const string TABLE_FORMAT = "| {0,-4} | {1,-32} | {2,-8} |\n";
                    var enabledCount = Logger.EnabledDebugCategories.Count(entry => entry.Value);
                    var totalCount = Enum.GetValues(typeof(DebugCategory)).Length;

                    StringBuilder sb = new($"Available debug categories ({enabledCount} of {totalCount} enabled):\n");
                    sb.Append(String.Format(TABLE_FORMAT, "ID", "Name", "Status"));
                    sb.Append(String.Format(TABLE_FORMAT, new string('-', 4), new string('-', 32), new string('-', 8)));
                    foreach (int catVal in Enum.GetValues(typeof(DebugCategory)))
                    {
                        string catName_Ls = Enum.GetName(typeof(DebugCategory), catVal) ?? "N/A";
                        string catStatus = Logger.EnabledDebugCategories.GetOrAdd((DebugCategory)catVal, false) ? "Enabled" : "Disabled";
                        sb.Append(String.Format(TABLE_FORMAT, $"#{catVal}", catName_Ls, catStatus));
                    }
                    Logger.WriteInfo("Debugging", sb.ToString());

                    break;
                default:
                    Logger.WriteErr("Debugging", $"Invalid subcommand. Usage: '{usage}'");
                    break;
            }

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
            CommandHandlers.AddLast(new DebugCategoryCommand());
            Console.CancelKeyPress += (_, ea) =>
            {
                ea.Cancel = true;
                Logger.WriteWarn("SharpGuard", "Received SIGINT/SIGTERM, stopping program...");
                sg.Stop();
            };
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
            Logger.WriteInfo("Main Menu", "Awaiting command... (use 'help' for help)");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" % ");
            Console.ForegroundColor = ConsoleColor.Blue;
            var cmd = Console.ReadLine() ?? "";
            Console.ForegroundColor = ConsoleColor.White;
            cmd = cmd.Trim();
            cmd = Regex.Replace(cmd, @"\s", " ");
            return cmd.Split(" ");
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0051:Remove unused private members", Justification = "<thinking about it...>")]
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

            if (cmd.Length == 0)
            {
                Logger.WriteErr("Main Menu", "Please enter a command. For help, type 'help'.");
                return false;
            }

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

            Logger.WriteErr("Main Menu", "Unrecognised command, please try again. For help, type 'help'.");
            return false;
        }
    }

    public enum DebugCategory : int
    {
        FILE_WATCHING,
        DETECTIONS_GENERIC,
        DETECTIONS_SEATBELT_FILEINFO,
        UNCATEGORISED
    }

}
