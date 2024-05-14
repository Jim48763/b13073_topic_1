rule deefebedcbdecabeecacffbfdcda_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "szUserMessage != NULL"
        $s3 = "SetConsoleCtrlHandler"
        $s4 = "JmhDbdf6>e8"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleA"
        $s7 = "PA[580227362014521203534]"
        $s8 = "Expression: "
        $s9 = "9A5F1F762014521203534=9A5F1F762014521203534"
        $s10 = "IsBadWritePtr"
        $s11 = "__MSVCRT_HEAP_SELECT"
        $s12 = "SetHandleCount"
        $s13 = "InterlockedDecrement"
        $s14 = "GetProcessHeap"
        $s15 = "VirtualProtect"
        $s16 = "zdI:6RYZv("
        $s17 = "(+c*jd3Ke/"
        $s18 = "Q'Z#/Nxq;@"
        $s19 = "GetCurrentProcess"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 361KB and
    4 of them
}
    
