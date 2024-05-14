rule cefaaebdaccdbeecfcffabedd_exe {
strings:
        $s1 = "_crt_debugger_hook"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "\\SGZSClient.exe"
        $s6 = "TerminateProcess"
        $s7 = "GetCurrentThreadId"
        $s8 = "GetTickCount"
        $s9 = "_invoke_watson"
        $s10 = "FormatMessageA"
        $s11 = "GetSystemTimeAsFileTime"
        $s12 = "getGameMarketID"
        $s13 = "GetCurrentProcess"
        $s14 = "_XcptFilter"
        $s15 = "MSVCP80.dll"
        $s16 = "IsDebuggerPresent"
        $s17 = "_controlfp_s"
        $s18 = "_adjust_fdiv"
        $s19 = "KERNEL32.dll"
        $s20 = "__getmainargs"
condition:
    uint16(0) == 0x5a4d and filesize < 129KB and
    4 of them
}
    
