rule bdfabbeeeedadadbfccfce_exe {
strings:
        $s1 = "_crt_debugger_hook"
        $s2 = "TerminateProcess"
        $s3 = "GetCurrentThreadId"
        $s4 = "GetTickCount"
        $s5 = "RNAo?uM_\"x\""
        $s6 = "_invoke_watson"
        $s7 = "Tenth of Degrees"
        $s8 = "    </security>"
        $s9 = "GetSystemTimeAsFileTime"
        $s10 = "ClipPrecision"
        $s11 = "Common Dialogs"
        $s12 = "`neGlSA3^s"
        $s13 = "Back Style"
        $s14 = "9[W{D1~_%0"
        $s15 = "m.Af|+_Yi["
        $s16 = "GetCurrentProcess"
        $s17 = "MSVCR90.dll"
        $s18 = "_XcptFilter"
        $s19 = "</assembly>"
        $s20 = "IsDebuggerPresent"
condition:
    uint16(0) == 0x5a4d and filesize < 424KB and
    4 of them
}
    
