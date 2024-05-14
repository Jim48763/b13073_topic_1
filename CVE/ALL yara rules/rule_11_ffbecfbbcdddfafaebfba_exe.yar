rule ffbecfbbcdddfafaebfba_exe {
strings:
        $s1 = "cross device link"
        $s2 = "executable format error"
        $s3 = "result out of range"
        $s4 = "directory not empty"
        $s5 = "invalid string position"
        $s6 = "operation canceled"
        $s7 = "GetConsoleOutputCP"
        $s8 = "LC_MONETARY"
        $s9 = "`local vftable'"
        $s10 = "spanish-venezuela"
        $s11 = "SetFilePointerEx"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "destination address required"
        $s15 = "GetCurrentThreadId"
        $s16 = "south-africa"
        $s17 = "resource deadlock would occur"
        $s18 = "device or resource busy"
        $s19 = "wrong protocol type"
        $s20 = "FindFirstFileExW"
condition:
    uint16(0) == 0x5a4d and filesize < 281KB and
    4 of them
}
    
