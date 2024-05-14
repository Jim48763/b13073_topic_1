rule ebbeafedabfbcaceeded_exe {
strings:
        $s1 = "cross device link"
        $s2 = "`vector destructor iterator'"
        $s3 = "CreateIoCompletionPort"
        $s4 = "executable format error"
        $s5 = "directory not empty"
        $s6 = "4=.8**.6+={y*<+0850"
        $s7 = "result out of range"
        $s8 = "invalid string position"
        $s9 = "On tree page %d cell %d: "
        $s10 = "operation canceled"
        $s11 = "GetConsoleOutputCP"
        $s12 = "`local vftable'"
        $s13 = "SetFilePointerEx"
        $s14 = "%z WITH INDEX %s"
        $s15 = "GetModuleHandleW"
        $s16 = "GetCurrentDirectoryW"
        $s17 = "destination address required"
        $s18 = "CreateCompatibleDC"
        $s19 = "connection refused"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 551KB and
    4 of them
}
    
