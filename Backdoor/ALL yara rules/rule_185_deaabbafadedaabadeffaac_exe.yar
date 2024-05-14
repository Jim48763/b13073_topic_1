rule deaabbafadedaabadeffaac_exe {
strings:
        $s1 = "'%s' is not a valid date"
        $s2 = "ECompressInternalError"
        $s3 = "rEJo}<k`nDi"
        $s4 = "DX%rzc+O-;#"
        $s5 = "vz'[#|FS$-L"
        $s6 = "P\"/JZ?[xDX"
        $s7 = "EZ'6vC-NMi`"
        $s8 = "O~q(V19hbsJ"
        $s9 = "YuyTDHVbWO2"
        $s10 = "LoadStringA"
        $s11 = "%>yH4jI2c-k"
        $s12 = "a:.mje%2B\""
        $s13 = "jtB|,'^X;kU"
        $s14 = "e{j$Ah?zJT("
        $s15 = "-3}CSe.+IYw"
        $s16 = "@tL#~Jky<7p"
        $s17 = "GRPKgyDlp7@"
        $s18 = "n*v$iLwVkt,"
        $s19 = "8J\"i2/,N=O"
        $s20 = "4(-HmED7S01"
condition:
    uint16(0) == 0x5a4d and filesize < 4530KB and
    4 of them
}
    
