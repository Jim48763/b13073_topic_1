rule bcccdcffaddcffafeedffbfaa_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "GetEnvironmentStrings"
        $s3 = "SetConsoleCtrlHandler"
        $s4 = "Switzerland"
        $s5 = "LC_MONETARY"
        $s6 = "english-jamaica"
        $s7 = "spanish-venezuela"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "InitializeCriticalSection"
        $s11 = "GetCurrentThreadId"
        $s12 = "spanish-costa rica"
        $s13 = "DigiCert1%0#"
        $s14 = "GetTickCount"
        $s15 = "IsBadWritePtr"
        $s16 = "IsValidLocale"
        $s17 = "__MSVCRT_HEAP_SELECT"
        $s18 = "trinidad & tobago"
        $s19 = "norwegian-nynorsk"
        $s20 = "SetHandleCount"
condition:
    uint16(0) == 0x5a4d and filesize < 146KB and
    4 of them
}
    
