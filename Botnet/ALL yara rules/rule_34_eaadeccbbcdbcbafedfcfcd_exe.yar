rule eaadeccbbcdbcbafedfcfcd_exe {
strings:
        $s1 = "GetComputerNameA"
        $s2 = "GetCurrentDirectoryW"
        $s3 = "CallNextHookEx"
        $s4 = "ExitProcess"
        $s5 = "user32.dll"
        $s6 = "kernel32.dll"
        $s7 = "GetFileSize"
        $s8 = "v8mT~tj>"
        $s9 = "UIi@`X*"
        $s10 = "WinExec"
        $s11 = "sw~zvo"
        $s12 = "`.data"
        $s13 = "&^QD]"
        $s14 = "m[Uv<"
        $s15 = ".RJJN"
        $s16 = ".text"
        $s17 = "rurqu"
condition:
    uint16(0) == 0x5a4d and filesize < 7KB and
    4 of them
}
    
