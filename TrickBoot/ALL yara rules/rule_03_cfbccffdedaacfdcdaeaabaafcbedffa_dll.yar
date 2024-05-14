rule cfbccffdedaacfdcdaeaabaafcbedffa_dll {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "invalid string position"
        $s3 = "DeviceIoControl"
        $s4 = "`local vftable'"
        $s5 = "qqvwtsE]sv hdqTEj"
        $s6 = "SetFilePointerEx"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "E%s}^stpprttq1E7E5s}^stpprEw"
        $s10 = "s}^stpprv}E{sv hztt"
        $s11 = "GtGEAEGs}^stpprwtcS"
        $s12 = "GetCurrentThreadId"
        $s13 = "DeE{sv qrfr'"
        $s14 = "FEjsv hVqmEc"
        $s15 = "SetEndOfFile"
        $s16 = "FindFirstFileExA"
        $s17 = "D\\ERsv qvfU8"
        $s18 = "qwEuEcsv hPtt"
        $s19 = "BwtyDwEuEls|_"
        $s20 = "Unknown exception"
condition:
    uint16(0) == 0x5a4d and filesize < 150KB and
    4 of them
}
    
