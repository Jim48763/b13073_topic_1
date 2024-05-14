rule baffbbaefbcbfdbbdbaed_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "S-K=`5n&+\""
        $s3 = "VarFileInfo"
        $s4 = "bomgpiaruci.iwa"
        $s5 = "AFX_DIALOG_LAYOUT"
        $s6 = "Dad zupabozusojay"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "GetCurrentThreadId"
        $s10 = "SetEndOfFile"
        $s11 = "GetTickCount"
        $s12 = "SetHandleCount"
        $s13 = "GetSystemTimeAsFileTime"
        $s14 = "InterlockedDecrement"
        $s15 = "VirtualProtect"
        $s16 = "GetProcessHeap"
        $s17 = "^/,aj\"P>S"
        $s18 = "IsProcessorFeaturePresent"
        $s19 = "GetCurrentProcess"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 164KB and
    4 of them
}
    
