using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using SharpGuard.Log;

namespace SharpGuard.CLI.Cmd
{
    /// <summary>
    /// This command aids in managing enabled debug categories to be logged during runtime.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal class DebugCategoryCommand : Command
    {
        private static readonly string name = "Debug Category Management";
        private static readonly string description = "Check or manage enabled debug categories to be logged.";
        private static readonly string[] aliases = { "debug-category", "dbg-category", "debug-cat", "dbg-cat" };
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
                case "ENABLE":
                    Execute_DebugCategory_Enable(args);
                    break;
                case "RM":
                case "DEL":
                case "REMOVE":
                case "DELETE":
                case "DISABLE":
                    Execute_DebugCategory_Disable(args);
                    break;
                case "LS":
                case "LIST":
                    Execute_DebugCategory_List(args);
                    break;
                default:
                    Logger.WriteErr("Debugging", $"Invalid subcommand. Usage: '{usage}'");
                    break;
            }

            return false;
        }

        private static void Execute_DebugCategory_List(string[] args)
        {
            if (args.Length != 1)
            {
                Logger.WriteErr("Debugging", $"Invalid number of arguments. Usage: '{aliases.First()} ls'.");
                return;
            }

            const string TABLE_FORMAT = "| {0,-4} | {1,-48} | {2,-8} |\n";
            int enabledCount = Logger.EnabledDebugCategories.Count(entry => entry.Value);
            int totalCount = Enum.GetValues(typeof(DebugCategory)).Length;

            StringBuilder sb = new($"Available debug categories ({enabledCount} of {totalCount} enabled):\n");
            sb.Append(string.Format(TABLE_FORMAT, "ID", "Name", "Status"));
            sb.Append(string.Format(TABLE_FORMAT, new string('-', 4), new string('-', 48), new string('-', 8)));
            foreach (int catVal in Enum.GetValues(typeof(DebugCategory)))
            {
                string catName_Ls = Enum.GetName(typeof(DebugCategory), catVal) ?? "N/A";
                string catStatus = Logger.EnabledDebugCategories.GetOrAdd((DebugCategory)catVal, false) ? "Enabled" : "Disabled";
                sb.Append(string.Format(TABLE_FORMAT, $"#{catVal}", catName_Ls, catStatus));
            }
            Logger.WriteInfo("Debugging", sb.ToString());
        }

        private static void Execute_DebugCategory_Disable(string[] args)
        {
            if (args.Length != 2)
            {
                Logger.WriteErr("Debugging", $"Invalid number of arguments. Usage: '{aliases.First()} rm <category>'.");
                return;
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
                    return;
                }

                Logger.WriteInfo("Debugging", "Success.");
                return;
            }

            DebugCategory cat_Rm;

            try
            {
                cat_Rm = ParseDebugCategory(catName_Rm);
            }
            catch (Exception)
            {
                Logger.WriteErr("Debugging", $"Unable to parse debug category '{catName_Rm}' by name or ID. To list available values, use the 'ls' subcommand.");
                return;
            }

            if (!Logger.EnabledDebugCategories.GetValueOrDefault(cat_Rm, false))
            {
                Logger.WriteWarn("Debugging", $"Category '{catName_Rm}' is already disabled.");
                return;
            }

            try
            {
                Logger.WriteInfo("Debugging", $"Disabling debug logging for category '{Enum.GetName(typeof(DebugCategory), cat_Rm)}'...");
                Logger.EnabledDebugCategories.Remove(cat_Rm, out _);
                Logger.WriteInfo("Debugging", $"Success.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("Debugging", $"Caught exception;\nMessage: {ex.Message};\nStack Trace: {ex.StackTrace}");
                return;
            }
        }

        private static void Execute_DebugCategory_Enable(string[] args)
        {
            if (args.Length != 2)
            {
                Logger.WriteErr("Debugging", $"Invalid number of arguments. Usage: '{aliases.First()} add <category>'.");
                return;
            }

            string catName_Add = args[1].ToUpper();

            if (catName_Add == "*")
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
                    return;
                }

                Logger.WriteInfo("Debugging", "Success.");
                return;
            }

            DebugCategory cat_Add;

            try
            {
                cat_Add = ParseDebugCategory(catName_Add);
            }
            catch (Exception)
            {
                Logger.WriteErr("Debugging", $"Unable to parse debug category '{catName_Add}' by name or ID. To list available values, use the 'ls' subcommand.");
                return;
            }

            if (Logger.EnabledDebugCategories.GetOrAdd(cat_Add, false))
            {
                Logger.WriteWarn("Debugging", $"Category '{catName_Add}' is already enabled.");
                return;
            }

            try
            {
                Logger.WriteInfo("Debugging", $"Enabling debug logging for category '{Enum.GetName(typeof(DebugCategory), cat_Add)}'...");
                Logger.EnabledDebugCategories.AddOrUpdate(cat_Add, true, (_, _) => true);
                Logger.WriteInfo("Debugging", $"Success.");
            }
            catch (Exception ex)
            {
                Logger.WriteErr("Debugging", $"Caught exception;\nMessage: {ex.Message};\nStack Trace: {ex.StackTrace}");
                return;
            }
        }

        private static DebugCategory ParseDebugCategory(string name)
        {
            try
            {
                return (DebugCategory)int.Parse(name);
            }
            catch (FormatException)
            {
                try
                {
                    return (DebugCategory)Enum.Parse(typeof(DebugCategory), name);
                }
                catch (ArgumentException)
                {
                    throw;
                }
            }
        }
    }

}
