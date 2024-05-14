rule ecacbbecfecafdafeffbaeeecb_exe {
strings:
        $s1 = "_crt_debugger_hook"
        $s2 = "VarFileInfo"
        $s3 = "FileDescription"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleA"
        $s6 = "GetCurrentThreadId"
        $s7 = "GetTickCount"
        $s8 = "__wgetmainargs"
        $s9 = "FormatMessageW"
        $s10 = "_invoke_watson"
        $s11 = "    </security>"
        $s12 = "GetSystemTimeAsFileTime"
        $s13 = "OpenProcessToken"
        $s14 = "VirtualProtect"
        $s15 = "Copyright "
        $s16 = "GetCurrentProcess"
        $s17 = "_XcptFilter"
        $s18 = "ExitProcess"
        $s19 = "MSVCR90.dll"
        $s20 = "IsDebuggerPresent"
condition:
    uint16(0) == 0x5a4d and filesize < 321KB and
    4 of them
}
    
