rule effabddccddcaffeebccdbeecfa_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "WinHttpTimeToSystemTime"
        $s3 = "Runtime Error!"
        $s4 = "invalid string position"
        $s5 = "GetConsoleOutputCP"
        $s6 = "DeviceIoControl"
        $s7 = "`local vftable'"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "CreateCompatibleDC"
        $s11 = "GetCurrentThreadId"
        $s12 = "glMatrixMode"
        $s13 = "WINSPOOL.DRV"
        $s14 = "SetWindowRgn"
        $s15 = "GetTopWindow"
        $s16 = "GetTickCount"
        $s17 = "CertSetCRLContextProperty"
        $s18 = "WriteConsoleA"
        $s19 = "Process32Next"
        $s20 = "DefFrameProcA"
condition:
    uint16(0) == 0x5a4d and filesize < 328KB and
    4 of them
}
    
