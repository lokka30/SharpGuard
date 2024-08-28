using SharpGuard.Log;
using System;
using System.IO;

namespace SharpGuard.File
{
    /// <summary>
    /// This class contains generic utilities used in SharpGuard for handling file system tasks,
    /// such as watching for file events (see <code>Watch(...)</code>).
    /// </summary>
    public partial class FileUtils
    {

        /// <summary>
        /// Watch for file system events for a file name of interest anywhere inside the provided directory
        /// (can be located in any recursive location within the chosen directory). Invokes an Action handler
        /// function when an event is received.
        /// </summary>
        /// <param name="dirPath">Path to parent directory of file; does not have to be direct parent</param>
        /// <param name="fileName">File name to watch events for</param>
        /// <param name="handler">Action to handle file event results</param>
        /// <returns>The resulting FileSystemWatcher object. Dispose of object when finished.</returns>
        public static FileSystemWatcher Watch(string dirPath, string fileName, Action<WatchedFileEvent> handler)
        {

            // Create FSW instance.
            FileSystemWatcher watcher = new(dirPath)
            {
                NotifyFilter = NotifyFilters.Attributes
                | NotifyFilters.CreationTime
                | NotifyFilters.DirectoryName
                | NotifyFilters.FileName
                | NotifyFilters.LastAccess
                | NotifyFilters.LastWrite
                | NotifyFilters.Security
                | NotifyFilters.Size
            };

            // Modify properties.
            watcher.Changed += (sender, e) => handler(new WatchedFileEvent(FileEventType.CHANGED, sender, e.FullPath, e.Name ?? e.FullPath));
            watcher.Created += (sender, e) => handler(new WatchedFileEvent(FileEventType.CREATED, sender, e.FullPath, e.Name ?? e.FullPath));
            watcher.Deleted += (sender, e) => handler(new WatchedFileEvent(FileEventType.DELETED, sender, e.FullPath, e.Name ?? e.FullPath));
            watcher.Renamed += (sender, e) => handler(new WatchedFileEvent(FileEventType.RENAMED, sender, "\"" + e.OldFullPath + "\" renamed to \"" + e.FullPath + "\"", e.Name ?? e.FullPath));
            watcher.Error += (sender, e) => handler(new WatchedFileEvent(FileEventType.ERROR, sender, e.GetException().Message, ""));
            watcher.Filter = fileName;
            watcher.IncludeSubdirectories = true;
            watcher.EnableRaisingEvents = true;

            // Issue debug log.
            Logger.WriteDebug(DebugCategory.FILEUTILS_WATCHING, "FileUtils.Watch", () => $"Watching dir '{dirPath}' with fileNameFilter '{fileName}' with handler method name '{handler.Method.Name}'.");

            // Return object so caller can dispose of it later (IDisposable).
            return watcher;
        }
    }
}
