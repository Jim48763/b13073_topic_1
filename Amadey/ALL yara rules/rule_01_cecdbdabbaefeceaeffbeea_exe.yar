rule cecdbdabbaefeceaeffbeea_exe {
strings:
        $s1 = "GetFileAttributesExA"
        $s2 = "<file unknown>"
        $s3 = "invalid string position"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "VarFileInfo"
        $s6 = "`local vftable'"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "invalid iterator range"
        $s10 = "EnterCriticalSection"
        $s11 = "GetConsoleCursorInfo"
        $s12 = "GetConsoleAliasesW"
        $s13 = "(((_Src))) != NULL"
        $s14 = "Expression: "
        $s15 = "SetEndOfFile"
        $s16 = "GetTickCount"
        $s17 = "sizeInBytes > retsize"
        $s18 = "g_controlfp_s"
        $s19 = "2 <= radix && radix <= 36"
        $s20 = "Unknown exception"
condition:
    uint16(0) == 0x5a4d and filesize < 342KB and
    4 of them
}
    
