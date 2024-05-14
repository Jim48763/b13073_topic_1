rule ecaabdfefcadafacffcbdaab_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "invalid string position"
        $s3 = "DeviceIoControl"
        $s4 = "`local vftable'"
        $s5 = "TerminateProcess"
        $s6 = "SetFilePointerEx"
        $s7 = "EnterCriticalSection"
        $s8 = "SetEndOfFile"
        $s9 = "FindFirstFileExA"
        $s10 = "Unknown exception"
        $s11 = "RtlCaptureContext"
        $s12 = "OpenSCManagerA"
        $s13 = "CorExitProcess"
        $s14 = "ControlService"
        $s15 = "LoadLibraryExW"
        $s16 = "`udt returning'"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "GetProcessHeap"
        $s19 = "AreFileApisANSI"
        $s20 = "INZzHNZ|^>OFLNF"
condition:
    uint16(0) == 0x5a4d and filesize < 184KB and
    4 of them
}
    
