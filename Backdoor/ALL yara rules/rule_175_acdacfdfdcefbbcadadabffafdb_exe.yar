rule acdacfdfdcefbbcadadabffafdb_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "<file unknown>"
        $s3 = "GetConsoleOutputCP"
        $s4 = "CopyFileExW"
        $s5 = "VarFileInfo"
        $s6 = "_Locale != NULL"
        $s7 = "`local vftable'"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "EnterCriticalSection"
        $s11 = "SetCurrentDirectoryW"
        $s12 = "WriteProfileSectionW"
        $s13 = "SetNamedPipeHandleState"
        $s14 = "(((_Src))) != NULL"
        $s15 = "Expression: "
        $s16 = "QueryActCtxW"
        $s17 = "GetTickCount"
        $s18 = "SetThreadContext"
        $s19 = "sizeInBytes > retsize"
        $s20 = "SetConsoleCursorPosition"
condition:
    uint16(0) == 0x5a4d and filesize < 277KB and
    4 of them
}
    
