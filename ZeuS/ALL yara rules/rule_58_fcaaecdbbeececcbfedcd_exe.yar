rule fcaaecdbbeececcbfedcd_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "TerminateProcess"
        $s6 = "CreateJobObjectW"
        $s7 = "GetModuleHandleW"
        $s8 = "GetCurrentThreadId"
        $s9 = "B'86J@PQoV~~"
        $s10 = "GetTickCount"
        $s11 = "4HG4z&G\"IP?>"
        $s12 = "SetHandleCount"
        $s13 = "CorExitProcess"
        $s14 = ";$<f<x<$=,=A=L=\">"
        $s15 = "GetSystemTimeAsFileTime"
        $s16 = "InterlockedDecrement"
        $s17 = ":P\"[kKv+@"
        $s18 = "Tvoyu mat!"
        $s19 = "ru\"s$t<cm"
        $s20 = "Copyright "
condition:
    uint16(0) == 0x5a4d and filesize < 199KB and
    4 of them
}
    
