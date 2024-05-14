rule dbebcbfbbeeabcffeedace_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "VN\"(#*}R4y"
        $s3 = "VarFileInfo"
        $s4 = "gitulurabojipoyuj"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleW"
        $s7 = "GetComputerNameW"
        $s8 = "EnterCriticalSection"
        $s9 = "GetLocalTime"
        $s10 = "GetTickCount"
        $s11 = "SetConsoleCursorPosition"
        $s12 = "IsBadWritePtr"
        $s13 = "WriteConsoleA"
        $s14 = "VerifyVersionInfoA"
        $s15 = "GlobalGetAtomNameW"
        $s16 = "CorExitProcess"
        $s17 = "SetHandleCount"
        $s18 = "sagzmeoleke.ewi"
        $s19 = "GetFileAttributesW"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 1098KB and
    4 of them
}
    
