using System;
using System.Runtime.Versioning;

namespace SharpGuard.CLI.Cmd
{
    /// <summary>
    /// Standard abstract Command logic.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal abstract class Command
    {

        /// <summary>
        /// Name of the command.
        /// </summary>
        public string Name { get; init; }

        /// <summary>
        /// Description of the command.
        /// </summary>
        public string Description { get; init; }

        /// <summary>
        /// Aliases of the commmand. The command can be ran via typing any of these items.
        /// 
        /// Aliases should only be in lowercase, not contain spaces or escape characters, and be easy enough to type.
        /// </summary>
        public string[] Aliases { get; init; }

        /// <summary>
        /// Usage example of the command. Typically, this will use the first alias item as the base command name.
        /// </summary>
        public string Usage { get; init; }

        /// <summary>
        /// Construct a Command via the provided details.
        /// Will run some background useful checks on the data.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="description"></param>
        /// <param name="aliases"></param>
        /// <param name="usage"></param>
        /// <exception cref="ArgumentException"></exception>
        public Command(string name, string description, string[] aliases, string usage)
        {
            Name = name;
            Description = description;
            Aliases = aliases;
            Usage = usage;

            CheckArgument_Aliases(Aliases);
        }

        /// <summary>
        /// Runs some checks on the Aliases of a command to ensure they're within rough expectations.
        /// </summary>
        /// <param name="aliases">Array of alias strings</param>
        /// <exception cref="ArgumentException">If any of the aliases do not meet requirements</exception>
        private static void CheckArgument_Aliases(string[] aliases)
        {
            foreach (string alias in aliases)
            {
                if (alias.Contains(' '))
                {
                    throw new ArgumentException($"Aliases '{alias}' shouldn't contain spaces");
                }

                if (!alias.Equals(alias.ToLower()))
                {
                    throw new ArgumentException($"Alias '{alias}' shouldn't contain uppercase characters");
                }

                if (alias.Length > 64)
                {
                    throw new ArgumentException($"Alias '{alias}' is far too long in length ({alias.Length} > 64)");
                }
            }
        }

        /// <summary>
        /// Execute command with provided args. If the command should cause the CLI to exit, return true.
        /// 
        /// As of writing, it is only supposed to return <code>true</code> when the <code>exit</code> command
        /// is ran, but this doesn't matter in practice, any command can choose to stop the program without issue.
        /// </summary>
        /// <param name="args">Arguments provided to run the command</param>
        /// <returns>Whether the program should exit as a result of the command</returns>
        public abstract bool Execute(string[] args);
    }

}
