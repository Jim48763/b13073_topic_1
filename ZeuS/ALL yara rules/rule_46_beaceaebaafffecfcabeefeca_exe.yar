rule beaceaebaafffecfcabeefeca_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "invalid string position"
        $s3 = "ProductName"
        $s4 = "VarFileInfo"
        $s5 = "`local vftable'"
        $s6 = "FileDescription"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleA"
        $s9 = "CreateCompatibleBitmap"
        $s10 = "GetCurrentThreadId"
        $s11 = "glMatrixMode"
        $s12 = "GetLocalTime"
        $s13 = "COMDLG32.dll"
        $s14 = "GetTickCount"
        $s15 = "GetSystemInfo"
        $s16 = "PageSetupDlgA"
        $s17 = "GetWindowRect"
        $s18 = "InvalidateRect"
        $s19 = "SetHandleCount"
        $s20 = "CorExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 258KB and
    4 of them
}
    
