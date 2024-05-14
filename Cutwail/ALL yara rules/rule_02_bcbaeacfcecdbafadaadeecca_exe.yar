rule bcbaeacfcecdbafadaadeecca_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "spanish-guatemala"
        $s3 = "Runtime Error!"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "CopyFileExW"
        $s6 = "VirtualLock"
        $s7 = "LC_MONETARY"
        $s8 = "VarFileInfo"
        $s9 = "spanish-venezuela"
        $s10 = "GetComputerNameW"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleW"
        $s13 = "GetCurrentDirectoryW"
        $s14 = "WriteProfileStringW"
        $s15 = "SetConsoleCursorInfo"
        $s16 = "ContinueDebugEvent"
        $s17 = "south-africa"
        $s18 = "GetLocalTime"
        $s19 = "RYSZQ[PYVXOu"
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 181KB and
    4 of them
}
    
