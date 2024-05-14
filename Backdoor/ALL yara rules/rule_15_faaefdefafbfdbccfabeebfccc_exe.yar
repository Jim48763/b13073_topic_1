rule faaefdefafbfdbccfabeebfccc_exe {
strings:
        $s1 = "TerminateProcess"
        $s2 = "waveOutSetVolume"
        $s3 = "GetModuleHandleW"
        $s4 = "EnterCriticalSection"
        $s5 = "ScriptLayout"
        $s6 = "NETAPI32.dll"
        $s7 = "GetTickCount"
        $s8 = "57*\"\"B0+pCg"
        $s9 = "SelectClipRgn"
        $s10 = "SetHandleCount"
        $s11 = "GetSystemTimeAsFileTime"
        $s12 = "InterlockedDecrement"
        $s13 = "VirtualProtect"
        $s14 = "@zO>.v!' 9"
        $s15 = "}TBa[5k&'m"
        $s16 = "`+K).P2v{Y"
        $s17 = "GetNearestPaletteIndex"
        $s18 = "IsProcessorFeaturePresent"
        $s19 = "9 9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9"
        $s20 = "WUSER32.DLL"
condition:
    uint16(0) == 0x5a4d and filesize < 204KB and
    4 of them
}
    
