rule aaccecdcadfbedbeabebbcbda_dll {
strings:
        $s1 = "NppShell Settings"
        $s2 = "Show dynamic icon"
        $s3 = "`vector destructor iterator'"
        $s4 = "CoInitializeEx"
        $s5 = "Runtime Error!"
        $s6 = "BeginBufferedPaint"
        $s7 = "_T.aVmd8k*;"
        $s8 = "VarFileInfo"
        $s9 = "DialogBoxParamW"
        $s10 = "`local vftable'"
        $s11 = "FileDescription"
        $s12 = "DllGetClassObject"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleW"
        $s15 = "Add context menu item"
        $s16 = "GetTextExtentPoint32W"
        $s17 = "CreateCompatibleDC"
        $s18 = "GetCurrentThreadId"
        $s19 = "GetTickCount"
        $s20 = "Unknown exception"
condition:
    uint16(0) == 0x5a4d and filesize < 342KB and
    4 of them
}
    
