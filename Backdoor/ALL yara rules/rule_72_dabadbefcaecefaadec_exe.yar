rule dabadbefcaecefaadec_exe {
strings:
        $s1 = "CreateThreadpoolTimer"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "TerminateProcess"
        $s4 = "SetFilePointerEx"
        $s5 = "SetThreadStackGuarantee"
        $s6 = "EnterCriticalSection"
        $s7 = "GetSystemTimeAsFileTime"
        $s8 = "GetProcessHeap"
        $s9 = "IsProcessorFeaturePresent"
        $s10 = "ExitProcess"
        $s11 = "IsDebuggerPresent"
        $s12 = "KERNEL32.dll"
        $s13 = "FlushFileBuffers"
        $s14 = "CabinetWClass"
        $s15 = "WriteConsoleW"
        $s16 = "GetProcAddress"
        $s17 = "2 2,2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
        $s18 = "DOMAIN error"
        $s19 = "CreateEventExW"
        $s20 = "DecodePointer"
condition:
    uint16(0) == 0x5a4d and filesize < 142KB and
    4 of them
}
    
