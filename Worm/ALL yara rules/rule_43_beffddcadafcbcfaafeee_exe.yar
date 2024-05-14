rule beffddcadafcbcfaafeee_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "nCKOzulMpcz1"
        $s4 = "N3h1cNUSLuwl"
        $s5 = "MethCallEngine"
        $s6 = " hIB6Ri?wj"
        $s7 = "a4ZHruHW8QV48"
        $s8 = "OriginalFilename"
        $s9 = "VS_VERSION_INFO"
        $s10 = "Translation"
        $s11 = "FileVersion"
        $s12 = "InternalName"
        $s13 = "MSVBVM60.DLL"
        $s14 = "BsOoPsh;Rs"
        $s15 = "huogvFtU4"
        $s16 = "OsDROs\\TPs"
        $s17 = "U%Mi&>h5"
        $s18 = "Qs&nPssnPs"
        $s19 = "<E,W,|!."
        $s20 = "VoeatKti"
condition:
    uint16(0) == 0x5a4d and filesize < 140KB and
    4 of them
}
    
