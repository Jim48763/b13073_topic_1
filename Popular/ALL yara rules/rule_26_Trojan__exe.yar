rule Trojan__exe {
strings:
        $s1 = "shutdown /f /r /t 0"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "VarFileInfo"
        $s5 = "_CorExeMain"
        $s6 = "PB_WindowID"
        $s7 = "dwExtraInfo"
        $s8 = "ThreadStaticAttribute"
        $s9 = "IsWindowVisible"
        $s10 = "KeyEventHandler"
        $s11 = "FileDescription"
        $s12 = "FrameworkElement"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleA"
        $s15 = "DispatchMessageA"
        $s16 = "Integer overflow"
        $s17 = "RemoveDirectoryA"
        $s18 = "AutoRestartShell"
        $s19 = "GetCurrentDirectoryA"
        $s20 = "InitializeCriticalSection"
condition:
    uint16(0) == 0x5a4d and filesize < 6825KB and
    4 of them
}
    
