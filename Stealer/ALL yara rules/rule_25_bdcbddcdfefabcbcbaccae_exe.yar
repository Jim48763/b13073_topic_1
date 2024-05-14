rule bdcbddcdfefabcbcbaccae_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "GetSystemPowerStatus"
        $s3 = "Runtime Error!"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "LC_MONETARY"
        $s6 = "VarFileInfo"
        $s7 = "r,TP;\"i.$w"
        $s8 = "english-jamaica"
        $s9 = "spanish-venezuela"
        $s10 = "chinese-singapore"
        $s11 = "AFX_DIALOG_LAYOUT"
        $s12 = "SetComputerNameW"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleW"
        $s15 = "GetCurrentDirectoryA"
        $s16 = "SetConsoleCursorInfo"
        $s17 = "ContinueDebugEvent"
        $s18 = "SetLocalTime"
        $s19 = "south africa"
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 445KB and
    4 of them
}
    
