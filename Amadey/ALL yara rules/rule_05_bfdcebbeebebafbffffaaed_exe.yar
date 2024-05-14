rule bfdcebbeebebafbffffaaed_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "invalid string position"
        $s3 = "GetConsoleOutputCP"
        $s4 = "p|\"oy+4Ydg"
        $s5 = "`local vftable'"
        $s6 = "TerminateProcess"
        $s7 = "CreateJobObjectW"
        $s8 = "GetModuleHandleW"
        $s9 = "EnterCriticalSection"
        $s10 = "SetCurrentDirectoryA"
        $s11 = "SetEndOfFile"
        $s12 = "SetLocalTime"
        $s13 = "GetTickCount"
        $s14 = "Unknown exception"
        $s15 = "CallNamedPipeW"
        $s16 = "SetHandleCount"
        $s17 = "`udt returning'"
        $s18 = "Greater Manchester1"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "InterlockedDecrement"
condition:
    uint16(0) == 0x5a4d and filesize < 203KB and
    4 of them
}
    
