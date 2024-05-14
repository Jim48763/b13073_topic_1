rule adbfafbacadfbdbdffbc_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "GetEnvironmentStrings"
        $s3 = "invalid string position"
        $s4 = "GetConsoleOutputCP"
        $s5 = "VarFileInfo"
        $s6 = "LC_MONETARY"
        $s7 = "A-'jUT%NVCm"
        $s8 = "english-jamaica"
        $s9 = "SetVolumeLabelA"
        $s10 = "`local vftable'"
        $s11 = "SetThreadPriority"
        $s12 = "spanish-venezuela"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleW"
        $s15 = "SetCurrentDirectoryW"
        $s16 = "InitializeCriticalSection"
        $s17 = "GetCurrentThreadId"
        $s18 = "spanish-costa rica"
        $s19 = "south-africa"
        $s20 = "SetLocalTime"
condition:
    uint16(0) == 0x5a4d and filesize < 211KB and
    4 of them
}
    
