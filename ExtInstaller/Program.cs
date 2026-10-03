using System;
using System.Collections.Generic;
using Microsoft.Win32;

// ===========================================================================
//  ExtInstaller  manages the MS SSO extension via HKLM Edge policy key.
//
//  Runs as NT AUTHORITY\SYSTEM  always has HKLM write access.
//  No UAC, no HKCU fallback, no gpupdate.
//
//  Options:
//    --add          write forcelist entry               (default)
//    --check        check if entry is present; exit 0=yes 1=no
//    --remove       delete the forcelist entry
//    --verbose / -v detailed output
// ===========================================================================

class Program
{
    const string EXT_ID     = "ppnbnpeolgkicgegkbkbjmhlideopiji";
    const string UPDATE_URL = "https://clients2.google.com/service/update2/crx";
    const string ENTRY      = EXT_ID + ";" + UPDATE_URL;

    const string EDGE_POLICY = @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist";

    static bool _verbose = false;

    static int Main(string[] args)
    {
        _verbose    = HasFlag(args, "--verbose") || HasFlag(args, "-v");
        bool remove = HasFlag(args, "--remove");
        bool check  = HasFlag(args, "--check");
        // --add is the default when neither --remove nor --check is specified

        if (check)  return CheckEntry(EDGE_POLICY, "Edge");
        if (remove) return RemoveEntry(EDGE_POLICY, "Edge");
        return AddEntry(EDGE_POLICY, "Edge");
    }

    static int AddEntry(string subKey, string label)
    {
        string fullPath = $@"HKLM\{subKey}";
        Verbose($"  [DBG] Opening {fullPath}");
        try
        {
            using (RegistryKey key = Registry.LocalMachine.CreateSubKey(subKey, writable: true))
            {
                if (key == null) { Log($"  [FAIL] {label}: could not open/create key ({fullPath})."); return 1; }

                // Dump existing entries
                string[] names = key.GetValueNames();
                Verbose($"  [DBG] {label}: {names.Length} existing value(s) in key:");
                foreach (string name in names)
                {
                    string val = key.GetValue(name) as string ?? "(non-string)";
                    Verbose($"         [{name}] = {val}");
                    if (val.StartsWith(EXT_ID, StringComparison.OrdinalIgnoreCase))
                    {
                        Log($"  [SKIP] {label}: already present as [{name}] = {val}");
                        return 0;
                    }
                }

                string idx = NextFreeIndex(key);
                key.SetValue(idx, ENTRY, RegistryValueKind.String);
                Log($"  [ OK ] {label}: wrote [{idx}] = {ENTRY}");

                // Verify
                string written = key.GetValue(idx) as string;
                Verbose($"  [DBG] {label}: verify read back [{idx}] = {written ?? "(null)"}");
                return 0;
            }
        }
        catch (Exception ex) { Log($"  [FAIL] {label}: {ex.Message}"); return 1; }
    }

    static int CheckEntry(string subKey, string label)
    {
        string fullPath = $@"HKLM\{subKey}";
        Verbose($"  [DBG] Opening {fullPath}");
        try
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(subKey, writable: false))
            {
                if (key == null) { Log($"  [NO ] {label}: key does not exist ({fullPath})."); return 1; }

                string[] names = key.GetValueNames();
                Verbose($"  [DBG] {label}: {names.Length} existing value(s) in key:");
                foreach (string name in names)
                {
                    string val = key.GetValue(name) as string ?? "(non-string)";
                    Verbose($"         [{name}] = {val}");
                    if (val.StartsWith(EXT_ID, StringComparison.OrdinalIgnoreCase))
                    {
                        Log($"  [YES] {label}: entry present as [{name}] = {val}");
                        return 0;
                    }
                }
                Log($"  [NO ] {label}: entry not found in key.");
                return 1;
            }
        }
        catch (Exception ex) { Log($"  [FAIL] {label}: {ex.Message}"); return 1; }
    }

    static int RemoveEntry(string subKey, string label)
    {
        string fullPath = $@"HKLM\{subKey}";
        Verbose($"  [DBG] Opening {fullPath}");
        try
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(subKey, writable: true))
            {
                if (key == null) { Log($"  [SKIP] {label}: key not found ({fullPath})."); return 0; }

                string[] names = key.GetValueNames();
                Verbose($"  [DBG] {label}: {names.Length} existing value(s) in key:");
                foreach (string name in names)
                    Verbose($"         [{name}] = {key.GetValue(name) as string ?? "(non-string)"}");

                var toDelete = new List<string>();
                foreach (string name in names)
                {
                    string val = key.GetValue(name) as string;
                    if (val != null && val.StartsWith(EXT_ID, StringComparison.OrdinalIgnoreCase))
                        toDelete.Add(name);
                }

                if (toDelete.Count == 0) { Log($"  [SKIP] {label}: entry not found."); return 0; }

                foreach (string name in toDelete)
                {
                    key.DeleteValue(name, throwOnMissingValue: false);
                    Log($"  [ OK ] {label}: removed [{name}].");
                }
                return 0;
            }
        }
        catch (Exception ex) { Log($"  [FAIL] {label}: {ex.Message}"); return 1; }
    }

    static string NextFreeIndex(RegistryKey key)
    {
        var used = new HashSet<int>();
        foreach (string name in key.GetValueNames())
        { int n; if (int.TryParse(name, out n)) used.Add(n); }
        for (int i = 1; ; i++) if (!used.Contains(i)) return i.ToString();
    }

    static bool HasFlag(string[] args, string flag)
    { foreach (var a in args) if (string.Equals(a, flag, StringComparison.OrdinalIgnoreCase)) return true; return false; }

    static void Log(string m)     => Console.WriteLine(m);
    static void Verbose(string m) { if (_verbose) Console.WriteLine(m); }
}
