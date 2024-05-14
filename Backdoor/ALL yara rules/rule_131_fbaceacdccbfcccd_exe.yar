rule fbaceacdccbfcccd_exe {
strings:
        $s1 = "TerminateProcess"
        $s2 = "waveOutSetVolume"
        $s3 = "GetModuleHandleW"
        $s4 = "EnterCriticalSection"
        $s5 = "PathGetArgsW"
        $s6 = "GetTickCount"
        $s7 = "WNetCancelConnectionA"
        $s8 = "StringFromIID"
        $s9 = "SetHandleCount"
        $s10 = "GetSystemTimeAsFileTime"
        $s11 = "InterlockedDecrement"
        $s12 = "GetDeviceCaps"
        $s13 = "VirtualProtect"
        $s14 = "\"L{6<y0et"
        $s15 = "IsProcessorFeaturePresent"
        $s16 = "9 9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9"
        $s17 = "AVIFileOpen"
        $s18 = "WUSER32.DLL"
        $s19 = "ExitProcess"
        $s20 = "MSVFW32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 176KB and
    4 of them
}
    
