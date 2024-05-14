rule bbbfbfebcffcbededefadbcafdcee_exe {
strings:
        $s1 = "ExitProcess"
        $s2 = "user32.dll"
        $s3 = "kernel32.dll"
        $s4 = "BeginPaint"
        $s5 = "AppendMenuA"
        $s6 = "AnyPopup"
        $s7 = "pvS;95I"
        $s8 = "WinExec"
        $s9 = "2+N^mU"
        $s10 = "`.data"
        $s11 = ".TSIR"
        $s12 = "Q;C?C"
        $s13 = ".text"
condition:
    uint16(0) == 0x5a4d and filesize < 7KB and
    4 of them
}
    
