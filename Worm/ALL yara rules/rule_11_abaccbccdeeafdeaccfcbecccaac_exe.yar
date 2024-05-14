rule abaccbccdeeafdeaccfcbecccaac_exe {
strings:
        $s1 = "RegSetValueExA"
        $s2 = "GetThreadLocale"
        $s3 = "GetKeyboardType"
        $s4 = "GetShortPathNameA"
        $s5 = "GetModuleHandleA"
        $s6 = "EnterCriticalSection"
        $s7 = "GetCurrentThreadId"
        $s8 = "CreateCompatibleDC"
        $s9 = "GetLocalTime"
        $s10 = "SetEndOfFile"
        $s11 = "FPUMaskValue"
        $s12 = "GetDriveTypeA"
        $s13 = "RegOpenKeyExA"
        $s14 = "StretchDIBits"
        $s15 = "CreateDirectoryA"
        $s16 = "GetSysColor"
        $s17 = "PACKAGEINFO"
        $s18 = "ExitProcess"
        $s19 = "DestroyIcon"
        $s20 = "ExtractIconA"
condition:
    uint16(0) == 0x5a4d and filesize < 45KB and
    4 of them
}
    
