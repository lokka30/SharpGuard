using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;

namespace SharpGuard.CLI.Cmd
{
    /// <summary>
    /// This command is used to list available commands, their description, usage, and aliases.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal class HelpCommand : Command
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
            foreach (Command handler in CommandHandlers)
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
                foreach (string alias in handler.Aliases)
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

}
