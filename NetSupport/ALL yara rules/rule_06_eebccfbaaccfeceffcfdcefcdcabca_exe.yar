rule eebccfbaaccfeceffcfdcefcdcabca_exe {
strings:
        $s1 = "_[Xg`\\ld_shba\\Y"
        $s2 = "XXZ``dggknnruvx{{"
        $s3 = "a*rZ w$-+4_"
        $s4 = "qtkps;MX4Qf"
        $s5 = "%Wj4C)lqh_V"
        $s6 = "\"q(wv}H8l~"
        $s7 = "G`htT9)k[2A"
        $s8 = "in.\"Y+}CZH"
        $s9 = "LoadStringW"
        $s10 = ":I#M%$ty\"L"
        $s11 = "\"uVT8Ez*~G"
        $s12 = "V:g(8CzJD;m"
        $s13 = "ProgramFilesDir"
        $s14 = "IsWindowVisible"
        $s15 = "DialogBoxParamW"
        $s16 = "Not enough memory"
        $s17 = "GetModuleHandleW"
        $s18 = "DispatchMessageW"
        $s19 = "CRC failed in %s"
        $s20 = "CreateCompatibleBitmap"
condition:
    uint16(0) == 0x5a4d and filesize < 2028KB and
    4 of them
}
    
