rule bfcbdadacadcedcdcdaecdebd_exe {
strings:
        $s1 = "hcessheProhinathTermT"
        $s2 = "RegSetValueExA"
        $s3 = "EExternalException"
        $s4 = "TActiveThreadArray"
        $s5 = "GetWindowDC"
        $s6 = "1>&iE`Q*^%3"
        $s7 = "ProductName"
        $s8 = "LoadStringA"
        $s9 = "VarFileInfo"
        $s10 = "FileDescription"
        $s11 = "GetKeyboardType"
        $s12 = "GetThreadLocale"
        $s13 = "Division by zero"
        $s14 = "DispatchMessageA"
        $s15 = "GetModuleHandleA"
        $s16 = "EnterCriticalSection"
        $s17 = "Microsoft Corporation"
        $s18 = "GetTextExtentPoint32A"
        $s19 = "GetCurrentThreadId"
        $s20 = "WindowFromDC"
condition:
    uint16(0) == 0x5a4d and filesize < 787KB and
    4 of them
}
    
