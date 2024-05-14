rule ffceccbcaaaceacfc_exe {
strings:
        $s1 = "colenivadehuhejewohij"
        $s2 = "CreateIoCompletionPort"
        $s3 = "Runtime Error!"
        $s4 = "VarFileInfo"
        $s5 = "`local vftable'"
        $s6 = "AFX_DIALOG_LAYOUT"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "EnterCriticalSection"
        $s10 = "Module32Next"
        $s11 = "GetTickCount"
        $s12 = "Unknown exception"
        $s13 = "SetHandleCount"
        $s14 = "FlushViewOfFile"
        $s15 = "SetTapePosition"
        $s16 = "`udt returning'"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "InterlockedDecrement"
        $s19 = "SetConsoleTitleA"
        $s20 = "ClientToScreen"
condition:
    uint16(0) == 0x5a4d and filesize < 237KB and
    4 of them
}
    
