rule adcafedaccabffaeedacc_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "invalid string position"
        $s3 = "VarFileInfo"
        $s4 = "CopyFileExA"
        $s5 = "SetVolumeLabelW"
        $s6 = "`local vftable'"
        $s7 = "Sun zisosativabiv"
        $s8 = "GetThreadPriority"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleA"
        $s11 = "WriteProfileSectionW"
        $s12 = "GetConsoleCursorInfo"
        $s13 = "ContinueDebugEvent"
        $s14 = "GetCurrentThreadId"
        $s15 = "SetLocalTime"
        $s16 = "GetTickCount"
        $s17 = "Beseno tosido nevofifaf"
        $s18 = "WriteConsoleA"
        $s19 = "Unknown exception"
        $s20 = "SetHandleCount"
condition:
    uint16(0) == 0x5a4d and filesize < 147KB and
    4 of them
}
    
