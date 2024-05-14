rule bbddbbdededaaceacbeaeddaae_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "GetEnvironmentStrings"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "SetConsoleOutputCP"
        $s7 = "VarFileInfo"
        $s8 = "LC_MONETARY"
        $s9 = "english-jamaica"
        $s10 = "`local vftable'"
        $s11 = "spanish-venezuela"
        $s12 = "GetModuleHandleA"
        $s13 = "TerminateProcess"
        $s14 = "SetSystemTimeAdjustment"
        $s15 = "SetConsoleCursorInfo"
        $s16 = "GetCurrentThreadId"
        $s17 = "GetTickCount"
        $s18 = "south-africa"
        $s19 = "POFOLAZIVUVUMIMUPIRIC"
        $s20 = "MapViewOfFile"
condition:
    uint16(0) == 0x5a4d and filesize < 874KB and
    4 of them
}
    
