rule abcaacfacdafccaeaecddfbfefecedb_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "N3h1cNUSLuwl"
        $s4 = "RefeGieortioreykrtnymrnty"
        $s5 = "MethCallEngine"
        $s6 = "DNlbzKLXKoz1"
        $s7 = "a4ZHruHW8QV48"
        $s8 = "OriginalFilename"
        $s9 = "VS_VERSION_INFO"
        $s10 = "Translation"
        $s11 = "FileVersion"
        $s12 = "InternalName"
        $s13 = "MSVBVM60.DLL"
        $s14 = "JeOxlnvQ.exe"
        $s15 = "BsOoPsh;Rs"
        $s16 = "OsDROs\\TPs"
        $s17 = "JeOxlnvQ"
        $s18 = "jGVc:~ k"
        $s19 = "/80nXINF"
        $s20 = "Qs&nPssnPs"
condition:
    uint16(0) == 0x5a4d and filesize < 161KB and
    4 of them
}
    
