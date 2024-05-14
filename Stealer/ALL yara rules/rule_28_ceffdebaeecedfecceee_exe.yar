rule ceffdebaeecedfecceee_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "Directory not empty"
        $s3 = "Runtime Error!"
        $s4 = "GetConsoleOutputCP"
        $s5 = "No child processes"
        $s6 = "ProductName"
        $s7 = "[?YGQj{>VxL"
        $s8 = ":t-joLFE'ds"
        $s9 = "VarFileInfo"
        $s10 = "%4ufAx],wj:"
        $s11 = "qc{F&1w3X0J"
        $s12 = "2OJ|vrMpXy6"
        $s13 = "`local vftable'"
        $s14 = "FileDescription"
        $s15 = "TerminateProcess"
        $s16 = "GetModuleHandleW"
        $s17 = "Operation not permitted"
        $s18 = "Microsoft Corporation"
        $s19 = "GetCurrentThreadId"
        $s20 = "No locks available"
condition:
    uint16(0) == 0x5a4d and filesize < 1029KB and
    4 of them
}
    
