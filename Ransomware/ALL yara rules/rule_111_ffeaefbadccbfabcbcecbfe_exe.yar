rule ffeaefbadccbfabcbcecbfe_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "FreeUserPhysicalPages"
        $s3 = "<file unknown>"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "GetConsoleOutputCP"
        $s6 = "'F54\"Prd(W"
        $s7 = "#'k!L,=n`9i"
        $s8 = "ktm_ObASg@4"
        $s9 = "2v}RAuglzW^"
        $s10 = "J|LA-7 c=^U"
        $s11 = "VirtualLock"
        $s12 = "VarFileInfo"
        $s13 = "CopyFileExA"
        $s14 = "`local vftable'"
        $s15 = "Process32FirstW"
        $s16 = "AFX_DIALOG_LAYOUT"
        $s17 = "TerminateProcess"
        $s18 = "GetModuleHandleW"
        $s19 = "SetSystemTimeAdjustment"
        $s20 = "SetCurrentDirectoryW"
condition:
    uint16(0) == 0x5a4d and filesize < 809KB and
    4 of them
}
    
