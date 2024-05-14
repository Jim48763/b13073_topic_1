rule cfffffeafedfddfbceecdcbcdcadaf_exe {
strings:
        $s1 = "FindFirstFileExA"
        $s2 = "ExitProcess"
        $s3 = "user32.dll"
        $s4 = "CloseHandle"
        $s5 = "kernel32.dll"
        $s6 = "WinExec"
        $s7 = "`.data"
        $s8 = "\\oExK"
        $s9 = "}aDiH"
        $s10 = "lsAgQ"
        $s11 = ".PSSM"
        $s12 = ".text"
        $s13 = "~t~z~"
condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    
