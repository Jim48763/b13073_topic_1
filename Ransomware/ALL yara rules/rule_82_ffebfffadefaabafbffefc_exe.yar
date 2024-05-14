rule ffebfffadefaabafbffefc_exe {
strings:
        $s1 = "EVariantBadVarTypeError"
        $s2 = "VirtualAllocEx"
        $s3 = "QueryServiceStatus"
        $s4 = "B'XjxaH/=n_"
        $s5 = "LoadStringA"
        $s6 = "YG8l`ifvrup"
        $s7 = "ALYac_RTSrv"
        $s8 = "GetKeyboardType"
        $s9 = "GetThreadLocale"
        $s10 = "GetModuleHandleA"
        $s11 = "TerminateProcess"
        $s12 = "Division by zero"
        $s13 = "WriteProcessMemory"
        $s14 = "GetCurrentThreadId"
        $s15 = "GetLocalTime"
        $s16 = "SetEndOfFile"
        $s17 = "FPUMaskValue"
        $s18 = "EResNotFound"
        $s19 = "EOutOfMemory"
        $s20 = "SetThreadContext"
condition:
    uint16(0) == 0x5a4d and filesize < 329KB and
    4 of them
}
    
