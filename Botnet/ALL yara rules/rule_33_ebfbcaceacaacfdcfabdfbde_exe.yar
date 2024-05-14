rule ebfbcaceacaacfdcfabdfbde_exe {
strings:
        $s1 = "FindFirstFileExA"
        $s2 = "AlignRects"
        $s3 = "ExitProcess"
        $s4 = "user32.dll"
        $s5 = "CloseHandle"
        $s6 = "CreateFileW"
        $s7 = "kernel32.dll"
        $s8 = "t{vzws|s"
        $s9 = "WinExec"
        $s10 = "`.data"
        $s11 = "r_E:}"
        $s12 = "12sTz"
        $s13 = "}nFRZ"
        $s14 = "cGqn:"
        $s15 = ".text"
        $s16 = ".JJKR"
        $s17 = "WRWv~"
condition:
    uint16(0) == 0x5a4d and filesize < 7KB and
    4 of them
}
    
