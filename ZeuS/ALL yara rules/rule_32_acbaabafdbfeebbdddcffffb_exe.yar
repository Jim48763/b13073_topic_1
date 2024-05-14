rule acbaabafdbfeebbdddcffffb_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "LoadStringW"
        $s3 = "TerminateProcess"
        $s4 = "DispatchMessageW"
        $s5 = "GetModuleHandleA"
        $s6 = "GetCurrentThreadId"
        $s7 = "hnRTcNlEMizz"
        $s8 = "fNSHzPtRnWtE"
        $s9 = "SetWindowPos"
        $s10 = "EcljiZCFERmN"
        $s11 = "GetTickCount"
        $s12 = "GetWindowRect"
        $s13 = "SetHandleCount"
        $s14 = "mLRhhKnvZWmKPi"
        $s15 = "    </security>"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "InterlockedDecrement"
        $s18 = "GetProcessHeap"
        $s19 = "GetMonitorInfoW"
        $s20 = "SMQTNKCUYR"
condition:
    uint16(0) == 0x5a4d and filesize < 236KB and
    4 of them
}
    
