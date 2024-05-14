rule accfdbbfecaddcaeedad_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "invalid string position"
        $s3 = "GetConsoleOutputCP"
        $s4 = "VarFileInfo"
        $s5 = "`local vftable'"
        $s6 = "TerminateProcess"
        $s7 = "GetModuleHandleW"
        $s8 = "GetCurrentThreadId"
        $s9 = "WriteProcessMemory"
        $s10 = "GetTickCount"
        $s11 = "AttachConsole"
        $s12 = "Unknown exception"
        $s13 = "SetHandleCount"
        $s14 = "CreateMailslotA"
        $s15 = "`udt returning'"
        $s16 = "SetTapePosition"
        $s17 = "GetFileAttributesW"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "InterlockedDecrement"
        $s20 = "GetConsoleTitleA"
condition:
    uint16(0) == 0x5a4d and filesize < 364KB and
    4 of them
}
    
