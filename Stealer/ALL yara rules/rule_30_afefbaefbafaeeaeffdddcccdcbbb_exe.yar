rule afefbaefbafaeeaeffdddcccdcbbb_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "`vector destructor iterator'"
        $s3 = "GetSystemPowerStatus"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "SetConsoleCtrlHandler"
        $s7 = "VirtualLock"
        $s8 = "CopyFileExA"
        $s9 = ":I%BMaZC*'r"
        $s10 = "LC_MONETARY"
        $s11 = "VarFileInfo"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "spanish-venezuela"
        $s15 = "ProductionVersion"
        $s16 = "chinese-singapore"
        $s17 = "AFX_DIALOG_LAYOUT"
        $s18 = "TerminateProcess"
        $s19 = "GetModuleHandleW"
        $s20 = "south africa"
condition:
    uint16(0) == 0x5a4d and filesize < 386KB and
    4 of them
}
    
