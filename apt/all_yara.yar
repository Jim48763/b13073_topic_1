import pe
rule ceccfeacedaedecbbadda_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "1.0.6, 6-Sept-2010"
        $s3 = "?456789:;<="
        $s4 = "VarFileInfo"
        $s5 = "ADSInternal.exe"
        $s6 = "TerminateProcess"
        $s7 = "GetModuleHandleW"
        $s8 = "      %d blocks, %d sorted, %d scanned"
        $s9 = "      bytes: mapping %d, "
        $s10 = "S:(ML;;NW;;;S-1-16-0)"
        $s11 = "        reconstructing block ..."
        $s12 = "NetworkService.exe"
        $s13 = "VerifyVersionInfoW"
        $s14 = "OpenSCManagerW"
        $s15 = "selectors %d, "
        $s16 = "CreateNamedPipeW"
        $s17 = "GetTempFileNameW"
        $s18 = "RegCreateKeyExW"
        $s19 = "test of your memory system."
        $s20 = "NullSessionPipes"
condition:
    uint16(0) == 0x5a4d and filesize < 62KB and
    4 of them
}
    
rule fefefdbbddcececafdeaabafefddabcaeec_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "_CorExeMain"
        $s4 = "get_MachineName"
        $s5 = "FileDescription"
        $s6 = "GetDirectoryName"
        $s7 = "BackgroundWorker"
        $s8 = "DirectorySeparatorChar"
        $s9 = "InitializeComponent"
        $s10 = "System.Net.Security"
        $s11 = "DecompressToDirectory"
        $s12 = "Synchronized"
        $s13 = "IAsyncResult"
        $s14 = "set_ShowIcon"
        $s15 = "System.Resources"
        $s16 = "DirectoryInfo"
        $s17 = "if-none-match"
        $s18 = "GeneratedCodeAttribute"
        $s19 = "application/json"
        $s20 = "defaultInstance"
condition:
    uint16(0) == 0x5a4d and filesize < 34KB and
    4 of them
}
    
rule beecccfbbaeadeaffdedfbebebfaaa_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "cross device link"
        $s4 = "last_insert_rowid"
        $s5 = "JetRetrieveColumn"
        $s6 = "CreateThreadpoolTimer"
        $s7 = "`vector destructor iterator'"
        $s8 = "onoffalseyestruextrafull"
        $s9 = " exceeds the maximum of "
        $s10 = "wrong # of entries in index "
        $s11 = "get_New_Edge_cookies"
        $s12 = "authorization denied"
        $s13 = "notification message"
        $s14 = " USING COVERING INDEX "
        $s15 = "executable format error"
        $s16 = "result out of range"
        $s17 = "directory not empty"
        $s18 = "invalid string position"
        $s19 = "On tree page %d cell %d: "
        $s20 = "ios_base::failbit set"
condition:
    uint16(0) == 0x5a4d and filesize < 1077KB and
    4 of them
}
    
rule bbbacccbedaabccaeecadfecbebbd_exe {
strings:
        $s1 = "GuardModifierflag"
        $s2 = "ThreadAmILastThread"
        $s3 = "FlagsAttribute"
        $s4 = "RuntimeHelpers"
        $s5 = "GetProcessesByName"
        $s6 = "ThreadIsTerminated"
        $s7 = "ComputeHash"
        $s8 = "ZwCreateSection"
        $s9 = "FileDescription"
        $s10 = "ThreadCycleTime"
        $s11 = "lpApplicationName"
        $s12 = "ThreadIoPriority"
        $s13 = "dwFillAttributes"
        $s14 = "ResolveEventArgs"
        $s15 = "ThreadIdealProcessor"
        $s16 = "WriteProcessMemory"
        $s17 = "lpReturnSize"
        $s18 = "UniqueThread"
        $s19 = "lpNumWritten"
        $s20 = "GetHINSTANCE"
condition:
    uint16(0) == 0x5a4d and filesize < 78KB and
    4 of them
}
    
rule fceadefdfebdfabbaeabe_exe {
strings:
        $s1 = "id-ce-extKeyUsage"
        $s2 = "`vector destructor iterator'"
        $s3 = "Certificate Policies"
        $s4 = "id-kp-timeStamping"
        $s5 = "?456789:;<="
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "`local vftable'"
        $s10 = "id-at-dnQualifier"
        $s11 = "TerminateProcess"
        $s12 = "SetFilePointerEx"
        $s13 = "BLINDING CONTEXT"
        $s14 = "EnterCriticalSection"
        $s15 = "SetCurrentDirectoryW"
        $s16 = "id-at-uniqueIdentifier"
        $s17 = "Microsoft Corporation"
        $s18 = "BLOWFISH-ECB"
        $s19 = "RSA with MD5"
        $s20 = "Unique Identifier"
condition:
    uint16(0) == 0x5a4d and filesize < 392KB and
    4 of them
}
    