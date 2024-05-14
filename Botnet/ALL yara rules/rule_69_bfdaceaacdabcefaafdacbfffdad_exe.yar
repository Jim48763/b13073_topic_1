rule bfdaceaacdabcefaafdacbfffdad_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "`vector destructor iterator'"
        $s3 = "GetFileAttributesExA"
        $s4 = "invalid string position"
        $s5 = "[1,j Fp\"=<"
        $s6 = "VarFileInfo"
        $s7 = "B5awn)W}t9e"
        $s8 = "\\8,eB)N883c0=-"
        $s9 = "`local vftable'"
        $s10 = "TerminateProcess"
        $s11 = "GetModuleHandleW"
        $s12 = "GetComputerNameW"
        $s13 = "EnterCriticalSection"
        $s14 = "kozoveyewelujurokonawuwo"
        $s15 = "WriteProcessMemory"
        $s16 = "m^M?mrHoB;47"
        $s17 = "GetTickCount"
        $s18 = "k;LiD1=bf=CH"
        $s19 = "WriteConsoleA"
        $s20 = "VerifyVersionInfoW"
condition:
    uint16(0) == 0x5a4d and filesize < 792KB and
    4 of them
}
    
