rule aeeeecadecbdafbfcaf_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "GetConsoleProcessList"
        $s3 = "GetConsoleOutputCP"
        $s4 = "FoldStringA"
        $s5 = "VarFileInfo"
        $s6 = "TerminateProcess"
        $s7 = "GetModuleHandleW"
        $s8 = "GetComputerNameA"
        $s9 = "GetCurrentThreadId"
        $s10 = "SetEndOfFile"
        $s11 = "GetTickCount"
        $s12 = "SetHandleCount"
        $s13 = "ProjectVersion"
        $s14 = "SetFileAttributesW"
        $s15 = "GetSystemTimeAsFileTime"
        $s16 = "InterlockedDecrement"
        $s17 = "hasizodinugij"
        $s18 = "GetConsoleTitleA"
        $s19 = "VirtualProtect"
        $s20 = "GetProcessHeap"
condition:
    uint16(0) == 0x5a4d and filesize < 289KB and
    4 of them
}
    
