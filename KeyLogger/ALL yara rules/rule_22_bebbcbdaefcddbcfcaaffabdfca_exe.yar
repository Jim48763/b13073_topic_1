rule bebbcbdaefcddbcfcaaffabdfca_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "VarFileInfo"
        $s3 = "LocalShrink"
        $s4 = "GetComputerNameW"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleW"
        $s7 = "GetCurrentThreadId"
        $s8 = "GetLocalTime"
        $s9 = "GetTickCount"
        $s10 = "IsBadWritePtr"
        $s11 = "WriteConsoleA"
        $s12 = "GlobalGetAtomNameW"
        $s13 = "VerifyVersionInfoA"
        $s14 = "SetHandleCount"
        $s15 = "CancelTimerQueueTimer"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "InterlockedDecrement"
        $s18 = "SetConsoleTitleA"
        $s19 = "VirtualProtect"
        $s20 = "AreFileApisANSI"
condition:
    uint16(0) == 0x5a4d and filesize < 205KB and
    4 of them
}
    
