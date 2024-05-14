import pe
rule fabfdbccbacfeefed_exe {
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
    
rule befccdbacefefffbccfddf_dll {
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
    
rule edcdebfdfabfedabdeabefdbdbc_exe {
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
    