rule aedbebbdebdbeecfadffe_dll {
strings:
        $s1 = "GetModuleHandleW"
        $s2 = "TerminateProcess"
        $s3 = "EnterCriticalSection"
        $s4 = "GetCurrentThreadId"
        $s5 = "GetTickCount"
        $s6 = "SetHandleCount"
        $s7 = "    </security>"
        $s8 = "</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD"
        $s9 = "2(3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3"
        $s10 = "GetSystemTimeAsFileTime"
        $s11 = "InterlockedDecrement"
        $s12 = "IsProcessorFeaturePresent"
        $s13 = "GetCurrentProcess"
        $s14 = "HeapDestroy"
        $s15 = "WUSER32.DLL"
        $s16 = "ExitProcess"
        $s17 = "IsDebuggerPresent"
        $s18 = "GetProcAddress"
        $s19 = "DOMAIN error"
        $s20 = "DecodePointer"
condition:
    uint16(0) == 0x5a4d and filesize < 37KB and
    4 of them
}
    
