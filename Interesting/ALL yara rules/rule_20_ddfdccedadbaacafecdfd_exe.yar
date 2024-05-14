rule ddfdccedadbaacafecdfd_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "TerminateProcess"
        $s3 = "GetModuleHandleA"
        $s4 = "GetTextExtentPoint32A"
        $s5 = "GetLocalTime"
        $s6 = "Es hora de formatear"
        $s7 = "IsBadWritePtr"
        $s8 = "WNetOpenEnumA"
        $s9 = "OpenSCManagerA"
        $s10 = "ControlService"
        $s11 = "SetHandleCount"
        $s12 = "GetCurrentProcess"
        $s13 = "GetSystemMetrics"
        $s14 = "ExitProcess"
        $s15 = "HeapDestroy"
        $s16 = "IsBadReadPtr"
        $s17 = "KERNEL32.dll"
        $s18 = "FlushFileBuffers"
        $s19 = "GetProcAddress"
        $s20 = "VirtualAlloc"
condition:
    uint16(0) == 0x5a4d and filesize < 55KB and
    4 of them
}
    
