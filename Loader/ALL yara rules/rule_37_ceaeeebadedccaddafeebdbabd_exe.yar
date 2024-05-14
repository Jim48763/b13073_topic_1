rule ceaeeebadedccaddafeebdbabd_exe {
strings:
        $s1 = "invalid string position"
        $s2 = "GetConsoleOutputCP"
        $s3 = "YRsU[u;L6wr"
        $s4 = "`local vftable'"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleW"
        $s7 = "GetCurrentDirectoryA"
        $s8 = "InitializeCriticalSection"
        $s9 = "GetCurrentThreadId"
        $s10 = "GetLocalTime"
        $s11 = "GetTickCount"
        $s12 = "SetEndOfFile"
        $s13 = "WriteConsoleA"
        $s14 = "Unknown exception"
        $s15 = "SetHandleCount"
        $s16 = "CorExitProcess"
        $s17 = "`udt returning'"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "TransmitCommChar"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 164KB and
    4 of them
}
    
