using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

// ===========================================================================
//  EdgeClone -- clone the current Edge Default profile and launch Edge
//               headless with the cloned profile.
//
//  Options:
//    --src <dir>    Edge User Data source dir (default: current user's)
//    --out <dir>    Clone destination (default: %TEMP%\EdgeBackup_<stamp>)
//    --ppid <pid>   Spoof the parent PID of the launched Edge process
//    --verbose / -v Verbose output
// ===========================================================================

class Program
{
    static readonly HashSet<string> SkipDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache",
        "blob_storage", "VideoDecodeStats", "VideoEncodeAccelerator",
        "optimization_guide_model_store",
    };

    static bool _verbose = false;

    static int Main(string[] args)
    {
        _verbose = HasFlag(args, "--verbose") || HasFlag(args, "-v");

        string srcDir   = GetOption(args, "--src");
        string outDir   = GetOption(args, "--out");
        string ppidStr  = GetOption(args, "--ppid");
        int    ppid     = 0;
        if (ppidStr != null && !int.TryParse(ppidStr, out ppid))
        { Error($"Invalid --ppid value: {ppidStr}"); return 1; }

        if (srcDir == null)
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            srcDir = Path.Combine(local, "Microsoft", "Edge", "User Data");
        }
        if (!Directory.Exists(srcDir))
        {
            Error($"Source Edge User Data not found: {srcDir}");
            return 1;
        }

        if (outDir == null)
        {
            string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            outDir = Path.Combine(Path.GetTempPath(), "EdgeBackup_" + stamp);
        }

        Info($"Source : {srcDir}");
        Info($"Clone  : {outDir}");

        Info("Copying profile...");
        try   { CopyUserData(srcDir, outDir); }
        catch (Exception ex) { Error($"Copy failed: {ex.Message}"); return 1; }
        Info("Copy done.");

        // Remove lock files so Edge doesn't complain about the profile being in use
        foreach (string lf in new[] { "lockfile", "SingletonLock", "SingletonSocket", "SingletonCookie", ".parentlock" })
        {
            string p = Path.Combine(outDir, lf);
            try { if (File.Exists(p)) { File.Delete(p); Verbose($"  Removed lock: {lf}"); } } catch { }
        }
        {
            string p = Path.Combine(outDir, "Default", "LOCK");
            try { if (File.Exists(p)) { File.Delete(p); Verbose("  Removed Default/LOCK"); } } catch { }
        }

        string edgeExe = FindEdge();
        if (edgeExe == null) { Error("Could not locate msedge.exe."); return 1; }

        string edgeArgs = $"\"--user-data-dir={outDir}\" --headless --disable-gpu";
        Verbose($"Launching: {edgeExe} {edgeArgs}");

        int pid;
        if (ppid > 0)
        {
            Verbose($"Spoofing parent PID: {ppid}");
            pid = LaunchWithParent(edgeExe, edgeArgs, ppid);
            if (pid < 0) { Error("CreateProcess with parent spoofing failed."); return 1; }
        }
        else
        {
            var psi = new ProcessStartInfo(edgeExe, edgeArgs)
            {
                UseShellExecute = false,
                WindowStyle     = ProcessWindowStyle.Hidden,
            };
            pid = Process.Start(psi).Id;
        }

        Info($"Edge running headless (PID {pid}).");
        Info($"Clone  : {outDir}");
        return 0;
    }



    // -----------------------------------------------------------------------
    //  Launch with spoofed parent PID
    // -----------------------------------------------------------------------
    static int LaunchWithParent(string exe, string args, int parentPid)
    {
        IntPtr hParent = OpenProcess(PROCESS_CREATE_PROCESS, false, parentPid);
        if (hParent == IntPtr.Zero) { Error($"OpenProcess({parentPid}) failed: {Marshal.GetLastWin32Error()}"); return -1; }

        IntPtr attrList = IntPtr.Zero;
        IntPtr pHandle  = IntPtr.Zero;
        try
        {
            // Calculate required attribute list size
            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attrList = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref size))
            { Error($"InitializeProcThreadAttributeList failed: {Marshal.GetLastWin32Error()}"); return -1; }

            // Store hParent in unmanaged memory so we can pass a pointer to it
            pHandle = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pHandle, hParent);

            if (!UpdateProcThreadAttribute(attrList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    pHandle, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
            { Error($"UpdateProcThreadAttribute failed: {Marshal.GetLastWin32Error()}"); return -1; }

            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
            si.lpAttributeList = attrList;

            PROCESS_INFORMATION pi;
            string cmdLine = $"\"{exe}\" {args}";
            bool ok = CreateProcess(null, cmdLine, IntPtr.Zero, IntPtr.Zero, false,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi);
            if (!ok) { Error($"CreateProcess failed: {Marshal.GetLastWin32Error()}"); return -1; }

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return pi.dwProcessId;
        }
        finally
        {
            if (attrList != IntPtr.Zero) { DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
            if (pHandle  != IntPtr.Zero) Marshal.FreeHGlobal(pHandle);
            CloseHandle(hParent);
        }
    }

    // P/Invoke
    const uint PROCESS_CREATE_PROCESS           = 0x0080;
    const uint EXTENDED_STARTUPINFO_PRESENT     = 0x00080000;
    const uint CREATE_NO_WINDOW                 = 0x08000000;
    const uint PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int    cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize;
        public int    dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    // -----------------------------------------------------------------------
    //  Profile copy
    // -----------------------------------------------------------------------
    static void CopyUserData(string src, string dst)
    {
        Directory.CreateDirectory(dst);
        foreach (string file in Directory.GetFiles(src))
            SafeCopyFile(file, Path.Combine(dst, Path.GetFileName(file)));
        foreach (string subDir in Directory.GetDirectories(src))
        {
            string name = Path.GetFileName(subDir);
            if (!string.Equals(name, "Default", StringComparison.OrdinalIgnoreCase))
            { Verbose($"  [SKIP dir] {name}"); continue; }
            CopyDirectory(subDir, Path.Combine(dst, name));
        }
    }

    static void CopyDirectory(string src, string dst)
    {
        Directory.CreateDirectory(dst);
        foreach (string file in Directory.GetFiles(src))
            SafeCopyFile(file, Path.Combine(dst, Path.GetFileName(file)));
        foreach (string subDir in Directory.GetDirectories(src))
        {
            string name = Path.GetFileName(subDir);
            if (SkipDirs.Contains(name)) { Verbose($"  [SKIP cache] {subDir}"); continue; }
            CopyDirectory(subDir, Path.Combine(dst, name));
        }
    }

    static void SafeCopyFile(string src, string dst)
    {
        try   { File.Copy(src, dst, overwrite: true); }
        catch (Exception ex) { Verbose($"  [SKIP file] {Path.GetFileName(src)}: {ex.Message}"); }
    }

    // -----------------------------------------------------------------------
    //  Locate msedge.exe
    // -----------------------------------------------------------------------
    static string FindEdge()
    {
        foreach (string rp in new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
        })
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(rp))
                {
                    string v = k?.GetValue(null) as string;
                    if (v != null && File.Exists(v)) return v;
                }
            }
            catch { }
        }
        foreach (string c in new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft", "Edge", "Application", "msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),    "Microsoft", "Edge", "Application", "msedge.exe"),
        })
            if (File.Exists(c)) return c;
        return null;
    }

    // -----------------------------------------------------------------------
    //  Helpers
    // -----------------------------------------------------------------------
    static bool HasFlag(string[] args, string flag)
    {
        foreach (var a in args)
            if (string.Equals(a, flag, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    static string GetOption(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        return null;
    }

    static void Info(string msg)    => Console.WriteLine(msg);
    static void Warn(string msg)    => Console.WriteLine($"[WARN] {msg}");
    static void Error(string msg)   => Console.WriteLine($"[ERR]  {msg}");
    static void Verbose(string msg) { if (_verbose) Console.WriteLine(msg); }
}
