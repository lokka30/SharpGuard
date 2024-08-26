using System;
using System.IO;

namespace SharpGuard
{
    internal class FileUtils
    {
        public enum FileEventType
        {
            CHANGED,
            CREATED,
            DELETED,
            RENAMED,
            ERROR
        }

        public readonly struct WatchedFileEvent
        {
            public WatchedFileEvent(FileEventType type, object sender, string descr, string fileName)
            {
                Type = type;
                Sender = sender;
                Descr = descr;
                FileName = fileName[(fileName.IndexOf('\\') + 1)..];
            }

            public FileEventType Type { get; init; }
            public object Sender { get; init; }
            public string Descr { get; init; }
            public string FileName { get; init; }
        }

        public static FileSystemWatcher Watch(string directoryPath, string fileNameFilter, Action<WatchedFileEvent> handler)
        {
            // FS Watcher
            var watcher = new FileSystemWatcher(directoryPath)
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

            watcher.Changed += (sender, e) => handler(new WatchedFileEvent(FileEventType.CHANGED, sender, e.FullPath, e.Name ?? e.FullPath));
            watcher.Created += (sender, e) => handler(new WatchedFileEvent(FileEventType.CHANGED, sender, e.FullPath, e.Name ?? e.FullPath));
            watcher.Deleted += (sender, e) => handler(new WatchedFileEvent(FileEventType.CHANGED, sender, e.FullPath, e.Name ?? e.FullPath));
            watcher.Renamed += (sender, e) => handler(new WatchedFileEvent(FileEventType.RENAMED, sender, "\"" + e.OldFullPath + "\" renamed to \"" + e.FullPath + "\"", e.Name ?? e.FullPath));
            watcher.Error += (sender, e) => handler(new WatchedFileEvent(FileEventType.CHANGED, sender, e.GetException().Message, "__error__"));

            watcher.Filter = fileNameFilter;
            watcher.IncludeSubdirectories = true;
            watcher.EnableRaisingEvents = true;

            Logger.WriteDebug(DebugCategory.FileWatching, "FileUtils.Watch", () => $"Watching dir '{directoryPath}' with fileNameFilter '{fileNameFilter}' with handler method name '{handler.Method.Name}'.");

            return watcher;
        }
    }
}
