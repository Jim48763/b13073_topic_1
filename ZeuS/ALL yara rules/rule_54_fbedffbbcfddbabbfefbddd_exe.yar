rule fbedffbbcfddbabbfefbddd_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "bsqyqEqUquqMqmq]q}1[\"+"
        $s3 = "Directory not empty"
        $s4 = "unittest._log)"
        $s5 = "requests.__version__)"
        $s6 = "SetConsoleCtrlHandler"
        $s7 = "No child processes"
        $s8 = "[>OU6yj9SiI"
        $s9 = "h')5:L_XM?;"
        $s10 = "htB#~j5}A{k"
        $s11 = "A=m%of]\">C"
        $s12 = "@q]c$m5PSFk"
        $s13 = "s@JjuplSF|_"
        $s14 = "3iza>1y|QV/"
        $s15 = ")kZ\"4-0$.F"
        $s16 = "d}!(xKBvE&3"
        $s17 = "e;i9VIoHMwt"
        $s18 = "L?;lfIU}y#e"
        $s19 = "\"Bv[ZK1,O$"
        $s20 = "l|uW[r#{`:J"
condition:
    uint16(0) == 0x5a4d and filesize < 13833KB and
    4 of them
}
    
