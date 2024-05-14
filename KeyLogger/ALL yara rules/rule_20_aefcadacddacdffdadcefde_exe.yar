rule aefcadacddacdffdadcefde_exe {
strings:
        $s1 = "_vsnprintf_helper"
        $s2 = "(ch != _T('\\0'))"
        $s3 = "CreateIoCompletionPort"
        $s4 = "dipemugotatumupikas"
        $s5 = "<file unknown>"
        $s6 = "omsphfoiokba`]"
        $s7 = "Runtime Error!"
        $s8 = "tufovotisuheladelo"
        $s9 = "GetConsoleOutputCP"
        $s10 = "Process32FirstW"
        $s11 = "`local vftable'"
        $s12 = "AFX_DIALOG_LAYOUT"
        $s13 = "GetModuleHandleA"
        $s14 = "TerminateProcess"
        $s15 = "SetCurrentDirectoryW"
        $s16 = "SetNamedPipeHandleState"
        $s17 = "GetConsoleCursorInfo"
        $s18 = "(((_Src))) != NULL"
        $s19 = "GetCurrentThreadId"
        $s20 = "SetLocalTime"
condition:
    uint16(0) == 0x5a4d and filesize < 388KB and
    4 of them
}
    
