rule befccdbacefefffbccfddf_dll {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "invalid string position"
        $s3 = "DeviceIoControl"
        $s4 = "`local vftable'"
        $s5 = "TerminateProcess"
        $s6 = "SetFilePointerEx"
        $s7 = "EnterCriticalSection"
        $s8 = "GtGEAEGs}^stpprwtcS"
        $s9 = "s}^stpprv}E{sv hztt"
        $s10 = "FEjsv hVqmEc"
        $s11 = "SetEndOfFile"
        $s12 = "DeE{sv qrfr'"
        $s13 = "DAEGsv qvf^&"
        $s14 = "FindFirstFileExA"
        $s15 = "qwEuEcsv hPtt"
        $s16 = "BwtyDwEuEls|_"
        $s17 = "D\\ERsv qvfU8"
        $s18 = "Unknown exception"
        $s19 = "OpenSCManagerA"
        $s20 = "CorExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 150KB and
    4 of them
}
    
