rule acfacddcccafdadaeecefb_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "msctls_progress32"
        $s3 = "Py_SetProgramName"
        $s4 = "spanish-guatemala"
        $s5 = "english-caribbean"
        $s6 = "Runtime Error!"
        $s7 = "RegSetValueExA"
        $s8 = "SetConsoleCtrlHandler"
        $s9 = "GetConsoleOutputCP"
        $s10 = "%s\\%s-wininst.log"
        $s11 = "LC_MONETARY"
        $s12 = "english-jamaica"
        $s13 = "spanish-venezuela"
        $s14 = "chinese-singapore"
        $s15 = "SetThreadPriority"
        $s16 = "RemoveDirectoryA"
        $s17 = "DispatchMessageA"
        $s18 = "TerminateProcess"
        $s19 = "GetModuleHandleA"
        $s20 = "Installing files..."
condition:
    uint16(0) == 0x5a4d and filesize < 213KB and
    4 of them
}
    
