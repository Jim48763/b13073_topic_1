rule efbbafaddcdcffaea_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "ExitProcess"
        $s3 = "GetProcAddress"
        $s4 = "LoadLibraryA"
        $s5 = ".rdata$zzzdbg"
        $s6 = "KERNEL32.DLL"
        $s7 = ".idata$5"
        $s8 = "\\$B*KWo"
        $s9 = "p}\\O`g)"
        $s10 = ".text$mn"
        $s11 = "_^ZY[]"
        $s12 = "UBMQ7?"
        $s13 = ".reloc"
        $s14 = "SQRVWj"
        $s15 = "?.XV[*"
        $s16 = "P 8B;|"
        $s17 = "$gO'wm"
        $s18 = "@.data"
        $s19 = "\\Q`{)"
        $s20 = "Rd\\F3"
condition:
    uint16(0) == 0x5a4d and filesize < 45KB and
    4 of them
}
    
