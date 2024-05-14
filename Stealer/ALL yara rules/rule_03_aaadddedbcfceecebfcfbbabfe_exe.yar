rule aaadddedbcfceecebfcfbbabfe_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "Directory not empty"
        $s3 = "SetConsoleCtrlHandler"
        $s4 = "No child processes"
        $s5 = "$=|LG)Mm;Tr"
        $s6 = "nRG Sf,`$58"
        $s7 = "HZi7;CG6Fl="
        $s8 = "()J8@G^t<j#"
        $s9 = "AV&,[MmpDag"
        $s10 = "A(3;RE1vP,'"
        $s11 = "F1;?)S~b&DL"
        $s12 = "Vq]JWYr*kh#"
        $s13 = "a5vCP|&hRB4"
        $s14 = "pIaV&w4K\"|"
        $s15 = "=-}c?RiEzul"
        $s16 = "q\"D|: b8$1"
        $s17 = "i^G<sRKz<GnG>']"
        $s18 = "`local vftable'"
        $s19 = "SetFilePointerEx"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 5157KB and
    4 of them
}
    
