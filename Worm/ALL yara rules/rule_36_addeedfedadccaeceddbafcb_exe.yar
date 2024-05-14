rule addeedfedadccaeceddbafcb_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "FileDescription"
        $s5 = "GetModuleHandleA"
        $s6 = "EnterCriticalSection"
        $s7 = "Microsoft Corporation"
        $s8 = "GetCurrentThreadId"
        $s9 = "GetSystemInfo"
        $s10 = "CorExitProcess"
        $s11 = "SetHandleCount"
        $s12 = "VirtualProtect"
        $s13 = "HeapDestroy"
        $s14 = "KERNEL32.dll"
        $s15 = "VirtualQuery"
        $s16 = "GetProcAddress"
        $s17 = "OriginalFilename"
        $s18 = "CoCreateInstance"
        $s19 = "DOMAIN error"
        $s20 = "VirtualAlloc"
condition:
    uint16(0) == 0x5a4d and filesize < 61KB and
    4 of them
}
    
