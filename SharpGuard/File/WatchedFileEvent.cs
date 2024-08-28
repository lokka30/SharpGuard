namespace SharpGuard.File
{
    public partial class FileUtils
    {
        /// <summary>
        /// Contains information about a FileSystemWatcher event with details that
        /// are likely useful for detections that watch for file system activity.
        /// 
        /// Properties are largely derived from the information provided from the
        /// FileSystemWatcher event data.
        /// </summary>
        public readonly struct WatchedFileEvent
        {
            public WatchedFileEvent(FileEventType type, object sender, string descr, string fileName)
            {
                Type = type;
                Sender = sender;
                Descr = descr;
                FileName = fileName[(fileName.IndexOf('\\') + 1)..]; // NOTE: This can include uppercase and lowercase characters!
            }

            public FileEventType Type { get; init; }
            public object Sender { get; init; }
            public string Descr { get; init; }
            public string FileName { get; init; }
        }
    }
}
