rule aeabebeccfbaecfceaebfc_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "l_pq~eyb79r"
        $s5 = "(L?F<Z1h8x9"
        $s6 = "FileDescription"
        $s7 = "DispatchMessageA"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleA"
        $s10 = "GetTextExtentPoint32W"
        $s11 = "GetCurrentThreadId"
        $s12 = "CreateCompatibleDC"
        $s13 = "Full Version"
        $s14 = "COMDLG32.dll"
        $s15 = "%7\"}!_[p,;!"
        $s16 = "?~+rKp^vkzkx"
        $s17 = "GetTickCount"
        $s18 = "ItemMenuClass"
        $s19 = "InvalidateRect"
        $s20 = "SetHandleCount"
condition:
    uint16(0) == 0x5a4d and filesize < 153KB and
    4 of them
}
    
