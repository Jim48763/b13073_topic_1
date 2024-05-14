rule ffbafdbeedadeecebbcfffffbfbefffba_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "VirtualAllocEx"
        $s3 = "[Caps Lock]"
        $s4 = "OThreadUnit"
        $s5 = "[Page Down]"
        $s6 = "GetKeyboardType"
        $s7 = "GetThreadLocale"
        $s8 = "HKEY_CLASSES_ROOT"
        $s9 = "SetThreadPriority"
        $s10 = "DispatchMessageA"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleA"
        $s13 = "UnhookWindowsHookEx"
        $s14 = "GetCurrentThreadId"
        $s15 = "WriteProcessMemory"
        $s16 = "GetLocalTime"
        $s17 = "TPUtilWindow"
        $s18 = "FPUMaskValue"
        $s19 = "SetEndOfFile"
        $s20 = "SetThreadContext"
condition:
    uint16(0) == 0x5a4d and filesize < 351KB and
    4 of them
}
    
