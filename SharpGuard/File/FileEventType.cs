namespace SharpGuard.File
{
    public partial class FileUtils
    {

        /// <summary>
        /// File event types mirroring possible results from the FileSystemWatcher.
        /// </summary>
        public enum FileEventType
        {
            CHANGED,
            CREATED,
            DELETED,
            RENAMED,
            ERROR
        }
    }
}
