using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SharpGuard
{
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

    class HelpCommand : Command
    {
        private static readonly string name = "help";
        private static readonly string description = "Show help for available commands.";
        private static readonly string[] aliases = { "help", "h", "man", "manual" };
        private static readonly string usage = "help";

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

    class ExitCommand : Command
    {
        private static readonly string name = "exit";
        private static readonly string description = "Exit the program.";
        private static readonly string[] aliases = { "exit", "ex", "quit", "q" };
        private static readonly string usage = "exit";

        public ExitCommand() : base(name, description, aliases, usage)
        {
        }

        public override bool Execute(string[] args)
        {
            Logger.WriteInfo("Exit", "Thank you and goodbye");
            return true;
        }
    }

    public class CLI
    {
        public LinkedList<Command> CommandHandlers { get; init; } = new();
        public bool IsVerbose { get; set; } = false;

        public CLI()
        {
            CommandHandlers.AddLast(new ExitCommand());
            CommandHandlers.AddLast(new HelpCommand(CommandHandlers));
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
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(" % ");
            Console.ForegroundColor = ConsoleColor.Blue;
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

    public class Logger
    {
        private BlockingCollection<Param> bc = new();

        public ConcurrentBag<DebugCategory> EnabledDebugCategories { get; private set; } = new() {
            DebugCategory.FileWatching,
            DebugCategory.Detections,
            DebugCategory.Detections_Seatbelt_FileInfo,
            DebugCategory.Uncategorised
        };

        public Logger()
        {
            Task.Factory.StartNew(() =>
            {
                foreach (var param in bc.GetConsumingEnumerable())
                {
                    switch (param.Type)
                    {
                        case "INFO":
                            WriteInfo(param.Prefix, param.Msg!!, param.Endl);
                            break;
                        case "WARN":
                            WriteWarn(param.Prefix, param.Msg!!, param.Endl);
                            break;
                        case "ERR":
                            WriteErr(param.Prefix, param.Msg!!, param.Endl);
                            break;
                        case "D":
                            WriteDebug(param.DebugCategory, param.Prefix, param.DebugMsg, param.Endl);
                            break;
                        default:
                            WriteErr("Invalid Log Params", param.ToString(), param.Endl);
                            break;
                    }
                }
            });
        }

        ~Logger()
        {
            bc.CompleteAdding();
        }

        public void WriteInfo(string prefix, string msg, bool endl = true)
        {
            WriteLine("INFO", ConsoleColor.Blue, prefix, msg, endl);
        }

        public void WriteWarn(string prefix, string msg, bool endl = true)
        {
            WriteLine("WARN", ConsoleColor.Yellow, prefix, msg, endl);
        }

        public void WriteErr(string prefix, string msg, bool endl = true)
        {
            WriteLine("ERR", ConsoleColor.Red, prefix, msg, endl);
        }

        public void WriteDebug(DebugCategory category, string prefix, Func<string> msg, bool endl = true)
        {
            if (!EnabledDebugCategories.Contains(category))
            {
                return;
            }

            var categoryToStr = Enum.GetName(category.GetType(), category) ?? "Unknown";

            WriteLine("D", (ConsoleColor) (((int) category) % 14) + 1, categoryToStr + " " + prefix, msg.Invoke(), endl, prefixColor: ConsoleColor.DarkGray, msgColor: ConsoleColor.DarkGray);
        }

        private void WriteLine(string levelPrefix, ConsoleColor levelColour, string msgPrefix, string msg, bool endl = true, ConsoleColor prefixColor = ConsoleColor.Blue, ConsoleColor msgColor = ConsoleColor.White)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("[" + DateTime.Now.ToShortTimeString() + " ");
            Console.ForegroundColor = levelColour;
            Console.Write(levelPrefix);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("] [");
            Console.ForegroundColor = prefixColor;
            Console.Write(msgPrefix);
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("]: ");
            Console.ForegroundColor = msgColor;

            if (endl)
            {
                Console.WriteLine(msg);
            }
            else
            {
                Console.Write(msg);
            }
            Console.ForegroundColor = ConsoleColor.White;
        }
    }
}
