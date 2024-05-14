rule ccdbebbefcfcdecffeedadb_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "VirtualLock"
        $s3 = "CopyFileExA"
        $s4 = "NL^Z*:'/SWz"
        $s5 = "JN$ VTLi7%R"
        $s6 = "?@B:cCL*bn-"
        $s7 = "VarFileInfo"
        $s8 = "AFX_DIALOG_LAYOUT"
        $s9 = "GetComputerNameA"
        $s10 = "TerminateProcess"
        $s11 = "GetModuleHandleW"
        $s12 = "SetSystemTimeAdjustment"
        $s13 = "WriteProfileStringW"
        $s14 = "GetConsoleCursorInfo"
        $s15 = "ContinueDebugEvent"
        $s16 = "GetCurrentThreadId"
        $s17 = "GetLocalTime"
        $s18 = "mIcQ%{J\\-vM"
        $s19 = "wXMT;W/_}A  "
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 404KB and
    4 of them
}
    
