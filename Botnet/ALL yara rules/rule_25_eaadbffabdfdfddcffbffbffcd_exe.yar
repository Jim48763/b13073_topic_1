rule eaadbffabdfdfddcffbffbffcd_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "invalid string position"
        $s3 = "VarFileInfo"
        $s4 = "GetThreadLocale"
        $s5 = "`local vftable'"
        $s6 = "bomgpiaruci.iwa"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "EnterCriticalSection"
        $s10 = "SetConsoleCursorInfo"
        $s11 = "GetConsoleAliasesW"
        $s12 = "GetConsoleFontSize"
        $s13 = "GetTickCount"
        $s14 = "Unknown exception"
        $s15 = "SetHandleCount"
        $s16 = "xujufotixasemet"
        $s17 = "`udt returning'"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "InterlockedDecrement"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 249KB and
    4 of them
}
    
