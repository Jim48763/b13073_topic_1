rule cddbabfadbfefbbafdffcbc_exe {
strings:
        $s1 = "NepIJsETgHM"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "MethCallEngine"
        $s5 = "OriginalFilename"
        $s6 = "VS_VERSION_INFO"
        $s7 = "Translation"
        $s8 = "FileVersion"
        $s9 = "InternalName"
        $s10 = "MSVBVM60.DLL"
        $s11 = "BsOoPsh;Rs"
        $s12 = "T+:D<}F{R"
        $s13 = "PsDROs\\TPs"
        $s14 = "uvvzdZFTy"
        $s15 = "EGNvhrbJ"
        $s16 = "Picture1"
        $s17 = "Sx4;e*yN"
        $s18 = "Qs&nPssnPs"
        $s19 = "?bdkMXbw"
        $s20 = "#-d2\"2="
condition:
    uint16(0) == 0x5a4d and filesize < 116KB and
    4 of them
}
    