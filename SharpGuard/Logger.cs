using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace SharpGuard
{
    public class Logger
    {
        public static ConcurrentDictionary<DebugCategory, bool> EnabledDebugCategories { get; private set; } = new();

        public static readonly object locker = new();

        public static void WriteInfo(string prefix, string msg, bool endl = true)
        {
            WriteLine("INFO", ConsoleColor.Blue, prefix, msg, endl);
        }

        public static void WriteWarn(string prefix, string msg, bool endl = true)
        {
            WriteLine("WARN", ConsoleColor.Yellow, prefix, msg, endl);
        }

        public static void WriteErr(string prefix, string msg, bool endl = true)
        {
            WriteLine("ERR", ConsoleColor.Red, prefix, msg, endl);
        }

        public static void WriteDebug(DebugCategory category, string prefix, Func<string> msg, bool endl = true)
        {
            if (!EnabledDebugCategories.GetValueOrDefault(category, false))
            {
                return;
            }

            var categoryToStr = Enum.GetName(category.GetType(), category) ?? "Unknown";

            WriteLine("D", (ConsoleColor)(((int)category) % 14) + 1, categoryToStr + " " + prefix, msg.Invoke(), endl, prefixColor: ConsoleColor.DarkGray, msgColor: ConsoleColor.DarkGray);
        }

        private static void WriteLine(string levelPrefix, ConsoleColor levelColour, string msgPrefix, string msg, bool endl = true, ConsoleColor prefixColor = ConsoleColor.Blue, ConsoleColor msgColor = ConsoleColor.White)
        {
            lock (locker)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("[" + DateTime.Now.ToString(new CultureInfo("en-au")) + " ");
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
}
