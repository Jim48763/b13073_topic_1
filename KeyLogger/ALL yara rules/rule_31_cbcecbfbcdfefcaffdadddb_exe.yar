rule cbcecbfbcdfefcaffdadddb_exe {
strings:
        $s1 = "get_ModuleName"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "k\"a:&v<$!."
        $s5 = "_CorExeMain"
        $s6 = "VarFileInfo"
        $s7 = "ProductName"
        $s8 = "FileDescription"
        $s9 = "QmpxdmNwc2Jwbw=="
        $s10 = "UGZnbG16ZmpzZw=="
        $s11 = "ResolveEventArgs"
        $s12 = "nme6RDg0mwgq3X3ee0m"
        $s13 = "AssemblyTitleAttribute"
        $s14 = "Tmp4YXl3amQ="
        $s15 = "QWtidWJyenM="
        $s16 = "RGFwZ210bQ=="
        $s17 = "Tnh4eXB6dHBl"
        $s18 = "VHJpdWNkcGd0"
        $s19 = "Wmh2bnBoZw=="
        $s20 = "RmhtZG1xaw=="
condition:
    uint16(0) == 0x5a4d and filesize < 646KB and
    4 of them
}
    
