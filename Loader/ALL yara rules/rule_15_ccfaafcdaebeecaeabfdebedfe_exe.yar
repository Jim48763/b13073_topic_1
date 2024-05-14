rule ccfaafcdaebeecaeabfdebedfe_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "GetEnvironmentStrings"
        $s3 = "GetSystemPowerStatus"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "VarFileInfo"
        $s6 = "LC_MONETARY"
        $s7 = "english-jamaica"
        $s8 = "AFX_DIALOG_LAYOUT"
        $s9 = "spanish-venezuela"
        $s10 = "TerminateProcess"
        $s11 = "GetModuleHandleW"
        $s12 = "SetComputerNameW"
        $s13 = "GetCurrentDirectoryA"
        $s14 = "EnterCriticalSection"
        $s15 = "SetConsoleCursorInfo"
        $s16 = "GetCurrentThreadId"
        $s17 = "spanish-costa rica"
        $s18 = "ContinueDebugEvent"
        $s19 = "south-africa"
        $s20 = "SetLocalTime"
condition:
    uint16(0) == 0x5a4d and filesize < 148KB and
    4 of them
}
    
