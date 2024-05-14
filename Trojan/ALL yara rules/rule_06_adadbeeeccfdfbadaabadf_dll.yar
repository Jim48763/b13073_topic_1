rule adadbeeeccfdfbadaabadf_dll {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "FileDescription"
        $s4 = "Microsoft Corporation"
        $s5 = "PrivateBuild"
        $s6 = "$~D;p%ZEMh]p"
        $s7 = "s.+8argu(\\{"
        $s8 = "87=7;!T%]U\\\\d'"
        $s9 = "Az~__GLOBAL_HEAP_S"
        $s10 = "VirtualProtect"
        $s11 = "Unknown excepE"
        $s12 = "LegalTrademarks"
        $s13 = "pac#f{&wi8"
        $s14 = "_5wvl71$Lg"
        $s15 = "R\"vVA+0Q<"
        $s16 = "type_infom"
        $s17 = "IK@ Cu6DAj"
        $s18 = "ihjvk\"lop"
        $s19 = "SpecialBuild"
        $s20 = "ADVAPI32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 81KB and
    4 of them
}
    
