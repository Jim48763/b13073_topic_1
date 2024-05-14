rule beccfafdebedcaaffdedebbacbfce_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "<file unknown>"
        $s3 = "invalid string position"
        $s4 = "kupadirokuxenovova"
        $s5 = "GetConsoleOutputCP"
        $s6 = "CopyFileExW"
        $s7 = ",*G{Y8Oj?k5"
        $s8 = "SetThreadLocale"
        $s9 = "`local vftable'"
        $s10 = "Process32FirstW"
        $s11 = "SetThreadPriority"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "EnterCriticalSection"
        $s15 = "SetCurrentDirectoryW"
        $s16 = "fipohenelodahopakaxehoya"
        $s17 = "(((_Src))) != NULL"
        $s18 = "Expression: "
        $s19 = "GetTickCount"
        $s20 = "sizeInBytes > retsize"
condition:
    uint16(0) == 0x5a4d and filesize < 251KB and
    4 of them
}
    
