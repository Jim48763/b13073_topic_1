rule aaaffddfcfefeaabfdcebaaffc_exe {
strings:
        $s1 = ", mscor}zb, Versz"
        $s2 = "em.Collvttions.Gv"
        $s3 = "exusFile\\ftpsite.ini"
        $s4 = "Google360Browser\\Browser"
        $s5 = "ser Data\\Default\\Web"
        $s6 = "j%Xjs[j\\Zj._jpYju^jrf"
        $s7 = "Plugins\\FTP\\Hosts"
        $s8 = "RuntimeHelpers"
        $s9 = "ZwResumeThread"
        $s10 = "awrfsux.Proper"
        $s11 = "Google\\Chrommodo\\Dragon"
        $s12 = "RuntimeFieldHandle"
        $s13 = "STAThreadAttribute"
        $s14 = "iEupkzVawco"
        $s15 = "Titan Browe"
        $s16 = "_ams <NEe?T"
        $s17 = "@CEGHJNPSTW"
        $s18 = "Config Path"
        $s19 = "ProductName"
        $s20 = "_CorExeMain"
condition:
    uint16(0) == 0x5a4d and filesize < 293KB and
    4 of them
}
    
