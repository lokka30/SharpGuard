using SharpGuard.Event;
using System;
using System.Runtime.Versioning;

namespace SharpGuard.Detection.Seatbelt
{
    /// <summary>
    /// Attempts to detect when Seatbelt's LOLBAS command is ran with the <code>-full</code> parameter
    /// (no filter used). This is achieved by monitoring files of interest.
    /// 
    /// See also: https://raw.githubusercontent.com/GhostPack/Seatbelt/master/Seatbelt/Commands/Misc/LOLBAS.cs
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class Detection_Seatbelt_Lolbas : Detection_FileAccessPattern
    {

        private static readonly string[] fileNames = {
            "advpack.dll", "appvlp.exe", "at.exe",
            "atbroker.exe", "bash.exe", "bginfo.exe",
            "bitsadmin.exe", "cl_invocation.ps1", "cl_mutexverifiers.ps1",
            "cdb.exe", "certutil.exe", "cmd.exe",
            "cmdkey.exe", "cmstp.exe", "comsvcs.dll",
            "control.exe", "csc.exe", "cscript.exe",
            "desktopimgdownldr.exe", "devtoolslauncher.exe", "dfsvc.exe",
            "diskshadow.exe", "dnscmd.exe", "dotnet.exe",
            "dxcap.exe", "esentutl.exe", "eventvwr.exe",
            "excel.exe", "expand.exe", "extexport.exe",
            "extrac32.exe", "findstr.exe", "forfiles.exe",
            "ftp.exe", "gfxdownloadwrapper.exe", "gpscript.exe",
            "hh.exe", "ie4uinit.exe", "ieadvpack.dll",
            "ieaframe.dll", "ieexec.exe", "ilasm.exe",
            "infdefaultinstall.exe", "installutil.exe", "jsc.exe",
            "makecab.exe", "manage-bde.wsf", "mavinject.exe",
            "mftrace.exe", "microsoft.workflow.compiler.exe", "mmc.exe",
            "msbuild.exe", "msconfig.exe", "msdeploy.exe",
            "msdt.exe", "mshta.exe", "mshtml.dll",
            "msiexec.exe", "netsh.exe", "odbcconf.exe",
            "pcalua.exe", "pcwrun.exe", "pcwutl.dll",
            "pester.bat", "powerpnt.exe", "presentationhost.exe",
            "print.exe", "psr.exe", "pubprn.vbs",
            "rasautou.exe", "reg.exe", "regasm.exe",
            "regedit.exe", "regini.exe", "register-cimprovider.exe",
            "regsvcs.exe", "regsvr32.exe", "replace.exe",
            "rpcping.exe", "rundll32.exe", "runonce.exe",
            "runscripthelper.exe", "sqltoolsps.exe", "sc.exe",
            "schtasks.exe", "scriptrunner.exe", "setupapi.dll",
            "shdocvw.dll", "shell32.dll", "slmgr.vbs",
            "sqldumper.exe", "sqlps.exe", "squirrel.exe",
            "syncappvpublishingserver.exe", "syncappvpublishingserver.vbs", "syssetup.dll",
            "tracker.exe", "tttracer.exe", "update.exe",
            "url.dll", "verclsid.exe", "wab.exe",
            "winword.exe", "wmic.exe", "wscript.exe",
            "wsl.exe", "wsreset.exe", "xwizard.exe",
            "zipfldr.dll", "csi.exe", "dnx.exe",
            "msxsl.exe", "ntdsutil.exe", "rcsi.exe",
            "te.exe", "vbc.exe", "vsjitdebugger.exe",
            "winrm.vbs"
        };

        private static readonly string nameOfTarget = "Seatbelt_LOLBAS";

        private static readonly EventID evid = EventID.DETECTION_SEATBELT_LOLBAS;

        private static readonly string dirName = @"C:\";

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
        public static readonly int timeKeyLowerBound = -3;

        /// <summary>
        /// Count # required to trigger alert
        /// </summary>
        public static readonly int countTriggerBound = fileNames.Length / 2;

        public Detection_Seatbelt_Lolbas(Action<Alert> onAlert, WinEventHandler eventHandler) :
            base(onAlert, eventHandler, dirName, millisPerBatch, millisPerCheck, timeKeyLowerBound, countTriggerBound, nameOfTarget, fileNames, evid)
        {
        }

    }
}
