rule edaefaacdecfeeeedffb_exe {
strings:
        $s1 = "EVariantBadVarTypeError"
        $s2 = "VirtualAllocEx"
        $s3 = "LoadStringA"
        $s4 = "?456789:;<="
        $s5 = "TWideStringList"
        $s6 = "GetKeyboardType"
        $s7 = "GetThreadLocale"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleA"
        $s10 = "DispatchMessageA"
        $s11 = "InitializeCriticalSection"
        $s12 = "1(1H1,7074787<7@7D8L8P8t8x8"
        $s13 = "WriteProcessMemory"
        $s14 = "GetCurrentThreadId"
        $s15 = "EInvalidCast"
        $s16 = "GetLocalTime"
        $s17 = "GetTickCount"
        $s18 = "SetEndOfFile"
        $s19 = "FPUMaskValue"
        $s20 = "EOutOfMemory"
condition:
    uint16(0) == 0x5a4d and filesize < 219KB and
    4 of them
}
    
