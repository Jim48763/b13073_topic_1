rule dffcbbceeeabacafdaecec_dll {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "bad function call"
        $s4 = "`vector destructor iterator'"
        $s5 = "Runtime Error!"
        $s6 = "SetConsoleCtrlHandler"
        $s7 = "GetConsoleOutputCP"
        $s8 = "LC_MONETARY"
        $s9 = "LoadStringA"
        $s10 = "english-jamaica"
        $s11 = "`local vftable'"
        $s12 = "spanish-venezuela"
        $s13 = "TerminateProcess"
        $s14 = "SetFilePointerEx"
        $s15 = "DispatchMessageA"
        $s16 = "SetThreadStackGuarantee"
        $s17 = "EnterCriticalSection"
        $s18 = "PathToRegion"
        $s19 = "&Meta Region"
        $s20 = "UpdateWindow"
condition:
    uint16(0) == 0x5a4d and filesize < 431KB and
    4 of them
}
    
