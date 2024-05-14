rule cfedbcadedeeabdbfbeefffded_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "Runtime Error!"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "GetConsoleOutputCP"
        $s7 = "LoadStringW"
        $s8 = "LC_MONETARY"
        $s9 = "english-jamaica"
        $s10 = "`local vftable'"
        $s11 = "DialogBoxParamW"
        $s12 = "spanish-venezuela"
        $s13 = "TerminateProcess"
        $s14 = "SetFilePointerEx"
        $s15 = "DispatchMessageW"
        $s16 = "SetThreadStackGuarantee"
        $s17 = "GetCurrentThreadId"
        $s18 = "OLEAUT32.dll"
        $s19 = "EnableWindow"
        $s20 = "south-africa"
condition:
    uint16(0) == 0x5a4d and filesize < 603KB and
    4 of them
}
    
