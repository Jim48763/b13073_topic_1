rule fbcfabbccdaaccdecbacbdcfcaaaffb_exe {
strings:
        $s1 = "UnloadUserProfile"
        $s2 = "^BXg3%9.O1P"
        $s3 = "yIgv0<4?`.>"
        $s4 = "6<F2/D!mW)3"
        $s5 = "HMmQql|B>:R"
        $s6 = "}]t-U?RiZls"
        $s7 = " !r#/v,x4pM"
        $s8 = "Xd%1u#!p4v8"
        $s9 = "@;{A2LtnDVU"
        $s10 = "ueDs,\"#S4a"
        $s11 = "7}'JlLRDq*Z"
        $s12 = "M.7g9N*Bn[>"
        $s13 = "3)7}Y6|{*V&"
        $s14 = "N9_E/I;~]o-"
        $s15 = "O_J$'7]b?9s"
        $s16 = "4C<7|@2/OL!"
        $s17 = "N_h>RV{w:gq"
        $s18 = "GetModuleHandleA"
        $s19 = "*CRYPT32.dll"
        $s20 = "gMUSER32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 7001KB and
    4 of them
}
    
