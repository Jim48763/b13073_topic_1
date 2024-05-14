rule ebcabeccafecfdfcfaddaf_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "spanish-guatemala"
        $s3 = "english-caribbean"
        $s4 = "Runtime Error!"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LC_MONETARY"
        $s9 = "english-jamaica"
        $s10 = "FileDescription"
        $s11 = "spanish-venezuela"
        $s12 = "chinese-singapore"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleA"
        $s15 = "PrivateBuild"
        $s16 = "south-africa"
        $s17 = "GetTickCount"
        $s18 = "trinidad & tobago"
        $s19 = "SetHandleCount"
        $s20 = "CorExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 144KB and
    4 of them
}
    
