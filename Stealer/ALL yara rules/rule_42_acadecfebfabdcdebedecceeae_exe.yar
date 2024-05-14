rule acadecfebfabdcdebedecceeae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "  Caption = Bmwkieaaiaat"
        $s3 = "Game@Trelokme.game1"
        $s4 = "CoInitializeEx"
        $s5 = "UY]9Qtw?'Xp"
        $s6 = ",/:~rzUY5Q;"
        $s7 = "9YpyVu^_>rK"
        $s8 = "-GFh;IdeE^n"
        $s9 = "G2-*k~YAD_["
        $s10 = "@tX}C(duqJ!"
        $s11 = "/forcse)un9"
        $s12 = "AG}t\"wY4S>"
        $s13 = "`zU{<Ru>S'5"
        $s14 = "QFLCPEOTDSB"
        $s15 = "BJk`}C^8]O9"
        $s16 = "GetModuleHandleA"
        $s17 = "K+]]4c'QR$\""
        $s18 = " jJT^(CVjg]W"
        $s19 = "MSVCP140.dll"
        $s20 = "Description:"
condition:
    uint16(0) == 0x5a4d and filesize < 1996KB and
    4 of them
}
    
