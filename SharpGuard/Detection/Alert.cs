using System;

namespace SharpGuard.Detection
{

    /// <summary>
    /// Contains various information about a detection's alert.
    /// </summary>
    public class Alert
    {

        /// <summary>
        /// Type of detection causing this alert.
        /// </summary>
        public AlertType Type { get; private set; }

        /// <summary>
        /// Short description of the alert, concisely describing
        /// what's happened and a brief summary of the context.
        /// </summary>
        public string ShortDesc { get; private set; }

        /// <summary>
        /// Full description of the alert, providing any other
        /// useful details for an analyst to investigate.
        /// </summary>
        public string FullDesc { get; private set; }

        /// <summary>
        /// Construct an alert with the provided details.
        /// </summary>
        /// <param name="type">Type of detection / category</param>
        /// <param name="shortDesc">Short description of alert</param>
        /// <param name="fullDesc">Full description of alert</param>
        public Alert(AlertType type, string shortDesc, string fullDesc)
        {
            Type = type;
            ShortDesc = shortDesc;
            FullDesc = fullDesc;
        }

        /// <summary>
        /// Create a readable string, useful for logging and displaying in event logs.
        /// </summary>
        /// <returns>Readable string describing alert</returns>
        public string ToReadableString()
        {
            string TypeAsName = Enum.GetName(typeof(AlertType), Type) ?? "Unknown";
            return $"Alert Info\n--------------\nCategory: \t{TypeAsName}\nShort Desc: \t{ShortDesc}\nFull Desc: \t{FullDesc}";
        }
    }
}
