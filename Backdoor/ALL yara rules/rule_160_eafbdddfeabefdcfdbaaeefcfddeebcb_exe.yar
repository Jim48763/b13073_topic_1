rule eafbdddfeabefdcfdbaaeefcfddeebcb_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "GetEnvironmentStrings"
        $s3 = "RegSetValueExA"
        $s4 = "GetConsoleOutputCP"
        $s5 = "ProductName"
        $s6 = "mKoSQnHypCM"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "SetThreadPriority"
        $s10 = "TerminateProcess"
        $s11 = "GetComputerNameA"
        $s12 = "GetModuleHandleW"
        $s13 = "0 2O2t2W4S6W6[6_6c6g6k6o6|6"
        $s14 = "EnterCriticalSection"
        $s15 = "GetLocalTime"
        $s16 = "SetEndOfFile"
        $s17 = "UpdateWindow"
        $s18 = "EnableWindow"
        $s19 = "GetTickCount"
        $s20 = "__vbaLenBstr"
condition:
    uint16(0) == 0x5a4d and filesize < 221KB and
    4 of them
}
    
