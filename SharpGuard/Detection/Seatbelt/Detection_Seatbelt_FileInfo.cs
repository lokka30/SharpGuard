using SharpGuard.Event;
using System;
using System.Runtime.Versioning;

namespace SharpGuard.Detection.Seatbelt
{
    /// <summary>
    /// Attempts to detect when Seatbelt's FileInfo command is ran with the <code>-full</code> parameter
    /// (no filter used). This is achieved by monitoring files of interest.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class Detection_Seatbelt_FileInfo : Detection_FileAccessPattern
    {

        private static readonly string[] fileNames = {
            "coremessaging.dll",
            "afd.sys",
            "mrxdav.sys",
            "dssvc.dll",
            "gdiplus.dll",
            "gpprefcl.dll",
            "ntoskrnl.exe",
            "pcadm.dll",
            "rpcrt4.dll",
            "shedsvc.dll",
            "seclogon.dll",
            "win32k.sys",
            "win32kfull.sys",
            "winload.exe",
            "winsrv.dll"
        };

        private static readonly string nameOfTarget = "Seatbelt_FileInfo";

        private static readonly EventID evid = EventID.DETECTION_SEATBELT_FILEINFO;

        private static readonly string dirName = @"C:\Windows\System32";

        /// <summary>
        /// Time between batches being separated, milliseconds
        /// </summary>
        public static readonly int millisPerBatch = 10_000;

        /// <summary>
        /// Time between scheduled checks, milliseconds
        /// </summary>
        public static readonly int millisPerCheck = 05_000;

        /// <summary>
        /// Lower bound for the time key; time keys lower than this are discarded
        /// </summary>
        public static readonly int timeKeyLowerBound = -2;

        /// <summary>
        /// Count # required to trigger alert
        /// </summary>
        public static readonly int countTriggerBound = 8;

        public Detection_Seatbelt_FileInfo(Action<Alert> onAlert, WinEventHandler eventHandler) :
            base(onAlert, eventHandler, dirName, millisPerBatch, millisPerCheck, timeKeyLowerBound, countTriggerBound, nameOfTarget, fileNames, evid)
        {
        }

    }
}
