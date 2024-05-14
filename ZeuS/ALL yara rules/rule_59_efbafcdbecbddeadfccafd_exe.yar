rule efbafcdbecbddeadfccafd_exe {
strings:
        $s1 = "CallMsgFilterA"
        $s2 = "VarFileInfo"
        $s3 = "@`$\" X]iG<"
        $s4 = "RemoveDirectoryA"
        $s5 = "UnregisterClassA"
        $s6 = "GetModuleHandleW"
        $s7 = "UpdateWindow"
        $s8 = "EnableWindow"
        $s9 = "GetScrollInfo"
        $s10 = "GetWindowRect"
        $s11 = "InvalidateRect"
        $s12 = "SetWindowLongW"
        $s13 = "CreateNamedPipeA"
        $s14 = "LsaFreeReturnBuffer"
        $s15 = "RegOpenKeyExW"
        $s16 = "ClientToScreen"
        $s17 = "ScreenToClient"
        $s18 = "GJE%@M-0xB"
        $s19 = "DragObject"
        $s20 = "CreateWaitableTimerW"
condition:
    uint16(0) == 0x5a4d and filesize < 203KB and
    4 of them
}
    
