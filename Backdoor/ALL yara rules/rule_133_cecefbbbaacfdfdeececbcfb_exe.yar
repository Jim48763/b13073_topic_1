rule cecefbbbaacfdfdeececbcfb_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "GetKeyboardLayout"
        $s3 = "VirtualAllocEx"
        $s4 = "MsgWindowClass"
        $s5 = "ProductName"
        $s6 = "IsWindowVisible"
        $s7 = "getcamsingleframe"
        $s8 = "RemoveDirectoryA"
        $s9 = "TerminateProcess"
        $s10 = "GetConsoleWindow"
        $s11 = "GetLastInputInfo"
        $s12 = "DispatchMessageA"
        $s13 = "GetModuleHandleA"
        $s14 = "CreateCompatibleBitmap"
        $s15 = "UnhookWindowsHookEx"
        $s16 = "WriteProcessMemory"
        $s17 = "GetLocalTime"
        $s18 = "ProgramFiles"
        $s19 = "GetTickCount"
        $s20 = "downloadfromlocaltofile"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
