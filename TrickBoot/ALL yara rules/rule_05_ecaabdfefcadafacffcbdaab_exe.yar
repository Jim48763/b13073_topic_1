rule ecaabdfefcadafacffcbdaab_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "invalid string position"
        $s3 = "JB~DHFeHOKKIMF~@HM"
        $s4 = "DeviceIoControl"
        $s5 = "`local vftable'"
        $s6 = "SetFilePointerEx"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "GetCurrentThreadId"
        $s10 = "SetEndOfFile"
        $s11 = "FindFirstFileExA"
        $s12 = "6NN :!=%< \"`+6+NN"
        $s13 = "Unknown exception"
        $s14 = "RtlCaptureContext"
        $s15 = "ControlService"
        $s16 = "LoadLibraryExW"
        $s17 = "OpenSCManagerA"
        $s18 = "`udt returning'"
        $s19 = "    </security>"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 184KB and
    4 of them
}
    