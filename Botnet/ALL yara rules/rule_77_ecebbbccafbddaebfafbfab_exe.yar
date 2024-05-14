rule ecebbbccafbddaebfafbfab_exe {
strings:
        $s1 = "|W]Y}$2+|@SK|<KF|"
        $s2 = "SetConsoleCtrlHandler"
        $s3 = "Nqd@EC\"YxL"
        $s4 = "BMQ8cd^IRSJ"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "FileDescription"
        $s8 = "274;?<FJGMQMIMI"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleW"
        $s11 = "EnterCriticalSection"
        $s12 = " +/8\\]UGKLC"
        $s13 = "\"%),%37.BG<"
        $s14 = "7DD(BL6<RK,>"
        $s15 = "IJBgg]XZP78."
        $s16 = "lgnoyoj}`cqi"
        $s17 = "DE>cdYWYO,-$"
        $s18 = "9:3`bWtunNNI"
        $s19 = "020\"65.1{zn"
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 369KB and
    4 of them
}
    