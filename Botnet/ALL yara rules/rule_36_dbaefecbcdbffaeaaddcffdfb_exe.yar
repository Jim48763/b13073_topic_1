rule dbaefecbcdbffaeaaddcffdfb_exe {
strings:
        $s1 = "GetBinaryType"
        $s2 = "AnimateWindow"
        $s3 = "FormatMessageA"
        $s4 = "ExitProcess"
        $s5 = "user32.dll"
        $s6 = "kernel32.dll"
        $s7 = "FreeConsole"
        $s8 = "txx{wp~t"
        $s9 = "WinExec"
        $s10 = "kG8\"}#"
        $s11 = "@D/_W<"
        $s12 = "`.data"
        $s13 = "zsyrz"
        $s14 = ".KKOL"
        $s15 = ".text"
        $s16 = "t{m|t"
condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    
