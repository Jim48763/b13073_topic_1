rule dbceffefdbdfccefdefba_exe {
strings:
        $s1 = "_vsnprintf_helper"
        $s2 = "(ch != _T('\\0'))"
        $s3 = "CreateIoCompletionPort"
        $s4 = "<file unknown>"
        $s5 = "Runtime Error!"
        $s6 = "VarFileInfo"
        $s7 = "SetVolumeLabelW"
        $s8 = "`local vftable'"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleW"
        $s11 = "GetCurrentDirectoryA"
        $s12 = "(((_Src))) != NULL"
        $s13 = "GetCurrentThreadId"
        $s14 = "Expression: "
        $s15 = "q.O|q]velI\""
        $s16 = ",LUzD8eJU+1c"
        $s17 = "GetTickCount"
        $s18 = "SetConsoleCursorPosition"
        $s19 = "(buf != NULL)"
        $s20 = "_write_nolock"
condition:
    uint16(0) == 0x5a4d and filesize < 366KB and
    4 of them
}
    
