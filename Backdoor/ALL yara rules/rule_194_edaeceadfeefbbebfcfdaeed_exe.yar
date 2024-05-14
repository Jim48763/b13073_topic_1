rule edaeceadfeefbbebfcfdaeed_exe {
strings:
        $s1 = "UnitInjectProcess"
        $s2 = "GetKeyboardLayout"
        $s3 = "OThreadUnit"
        $s4 = "[Page Down]"
        $s5 = "GetThreadLocale"
        $s6 = "SetThreadPriority"
        $s7 = "HKEY_CLASSES_ROOT"
        $s8 = "TerminateProcess"
        $s9 = "DispatchMessageA"
        $s10 = "GetModuleHandleA"
        $s11 = "EnterCriticalSection"
        $s12 = "WriteProcessMemory"
        $s13 = "GetCurrentThreadId"
        $s14 = "GetLocalTime"
        $s15 = "SetEndOfFile"
        $s16 = "'P\":'R>6!0%"
        $s17 = "FPUMaskValue"
        $s18 = "TPUtilWindow"
        $s19 = "SetThreadContext"
        $s20 = "VirtualFreeEx"
condition:
    uint16(0) == 0x5a4d and filesize < 519KB and
    4 of them
}
    
