rule fcedbcdcfbbffabefdafe_exe {
strings:
        $s1 = "CompareFileTime"
        $s2 = "CreateDirectoryW"
        $s3 = "ExitProcess"
        $s4 = "user32.dll"
        $s5 = "CloseHandle"
        $s6 = "kernel32.dll"
        $s7 = "WinExec"
        $s8 = "xs|~{k"
        $s9 = "`.data"
        $s10 = " J*PI"
        $s11 = ".OJPN"
        $s12 = "yzp{y"
        $s13 = ".text"
        $s14 = "zq~uz"
condition:
    uint16(0) == 0x5a4d and filesize < 7KB and
    4 of them
}
    
