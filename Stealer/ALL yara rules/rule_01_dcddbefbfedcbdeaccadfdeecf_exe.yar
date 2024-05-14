rule dcddbefbfedcbdeaccadfdeecf_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "`vector destructor iterator'"
        $s3 = "CreateIoCompletionPort"
        $s4 = "divapebinumumibelabigiweyiwi"
        $s5 = "Directory not empty"
        $s6 = "punutobobibulidiburazayuzicu"
        $s7 = "<file unknown>"
        $s8 = "Runtime Error!"
        $s9 = "No child processes"
        $s10 = "CopyFileExW"
        $s11 = "VarFileInfo"
        $s12 = "`local vftable'"
        $s13 = "SetThreadLocale"
        $s14 = "ranuzokakepayig"
        $s15 = "GetThreadPriority"
        $s16 = "GetModuleHandleW"
        $s17 = "Operation not permitted"
        $s18 = "GetCurrentDirectoryW"
        $s19 = "WriteProfileStringW"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 247KB and
    4 of them
}
    
