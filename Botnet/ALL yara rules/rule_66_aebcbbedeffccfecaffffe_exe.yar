rule aebcbbedeffccfecaffffe_exe {
strings:
        $s1 = "Lazexohex xewiset gepes"
        $s2 = "VarFileInfo"
        $s3 = "nx #sPi\"Mw"
        $s4 = "GetThreadLocale"
        $s5 = "`local vftable'"
        $s6 = "bomgpiaruci.iwa"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "psoxapexadiwisejipokoh"
        $s10 = "EnterCriticalSection"
        $s11 = "SetConsoleCursorInfo"
        $s12 = "GetConsoleAliasesW"
        $s13 = "GetTickCount"
        $s14 = "GetDevicePowerState"
        $s15 = "Unknown exception"
        $s16 = "SetHandleCount"
        $s17 = "`udt returning'"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "InterlockedDecrement"
        $s20 = "Nig mija lagovozo"
condition:
    uint16(0) == 0x5a4d and filesize < 155KB and
    4 of them
}
    
