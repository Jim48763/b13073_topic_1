rule daffbdcafefbaabedeafadea_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "`vector destructor iterator'"
        $s3 = "vonaxacaboxebatayunusi"
        $s4 = "Wifawuvi fitowaxexe"
        $s5 = "<file unknown>"
        $s6 = "VarFileInfo"
        $s7 = "QueryDosDeviceW"
        $s8 = "`local vftable'"
        $s9 = "TerminateProcess"
        $s10 = "bewopudokomajehu"
        $s11 = "GetModuleHandleW"
        $s12 = "EnterCriticalSection"
        $s13 = "(((_Src))) != NULL"
        $s14 = "6OXh&9!V @ W"
        $s15 = "Expression: "
        $s16 = "GetTickCount"
        $s17 = "FindFirstFileExA"
        $s18 = "SetConsoleCursorPosition"
        $s19 = "GetCursorInfo"
        $s20 = "VerifyVersionInfoA"
condition:
    uint16(0) == 0x5a4d and filesize < 296KB and
    4 of them
}
    
