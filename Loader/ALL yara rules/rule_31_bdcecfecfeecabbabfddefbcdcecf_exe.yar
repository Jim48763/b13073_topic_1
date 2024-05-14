rule bdcecfecfeecabbabfddefbcdcecf_exe {
strings:
        $s1 = "numberNegativePattern"
        $s2 = "FlagsAttribute"
        $s3 = "RuntimeHelpers"
        $s4 = "$this.GridSize"
        $s5 = "RuntimeFieldHandle"
        $s6 = "STAThreadAttribute"
        $s7 = "4_6>Y; 7N,W"
        $s8 = "ComputeHash"
        $s9 = "e3{>qMJ(U#:"
        $s10 = "VarFileInfo"
        $s11 = "ProductName"
        $s12 = "']LE^Ck@1\""
        $s13 = "_CorExeMain"
        $s14 = "Z&~*Vwr)jU8"
        $s15 = "FileDescription"
        $s16 = "FlushFinalBlock"
        $s17 = "Acer Incorporated"
        $s18 = "customCultureName"
        $s19 = "ResolveEventArgs"
        $s20 = "S3Vqd3d5eGV3cWo="
condition:
    uint16(0) == 0x5a4d and filesize < 1649KB and
    4 of them
}
    
