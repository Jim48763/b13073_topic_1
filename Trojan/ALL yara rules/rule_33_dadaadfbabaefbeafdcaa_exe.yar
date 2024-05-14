rule dadaadfbabaefbeafdcaa_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "`vector destructor iterator'"
        $s3 = "<file unknown>"
        $s4 = "Runtime Error!"
        $s5 = "CopyFileExW"
        $s6 = "jVWX$nGy7l&"
        $s7 = "`local vftable'"
        $s8 = "_Locale != NULL"
        $s9 = "gokufemologabivev"
        $s10 = "GetComputerNameA"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleW"
        $s13 = "SetSystemTimeAdjustment"
        $s14 = "SetCurrentDirectoryA"
        $s15 = "WriteProfileStringW"
        $s16 = "GetConsoleCursorInfo"
        $s17 = "GetCurrentThreadId"
        $s18 = "(((_Src))) != NULL"
        $s19 = "SetLocalTime"
        $s20 = "Expression: "
condition:
    uint16(0) == 0x5a4d and filesize < 437KB and
    4 of them
}
    
