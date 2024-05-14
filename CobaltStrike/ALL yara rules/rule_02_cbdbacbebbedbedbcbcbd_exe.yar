rule cbdbacbebbedbedbcbcbd_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "invalid string position"
        $s3 = "SetConsoleCtrlHandler"
        $s4 = "GetConsoleOutputCP"
        $s5 = "VarFileInfo"
        $s6 = "`local vftable'"
        $s7 = "AFX_DIALOG_LAYOUT"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "InitializeCriticalSection"
        $s11 = "GetCurrentThreadId"
        $s12 = "WriteProcessMemory"
        $s13 = "GetTickCount"
        $s14 = "Unknown exception"
        $s15 = "SetHandleCount"
        $s16 = "CreateMailslotW"
        $s17 = "`udt returning'"
        $s18 = "SetTapePosition"
        $s19 = "GenerateConsoleCtrlEvent"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 282KB and
    4 of them
}
    
