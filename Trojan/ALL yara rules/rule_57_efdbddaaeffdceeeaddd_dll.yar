rule efdbddaaeffdceeeaddd_dll {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "GetModuleBaseName"
        $s3 = "ConditionalAttribute"
        $s4 = "ManagementBaseObject"
        $s5 = "RuntimeHelpers"
        $s6 = "RuntimeFieldHandle"
        $s7 = "h()I*q p\"f"
        $s8 = "#6kA/\"*XbG"
        $s9 = "ProductName"
        $s10 = "#6k@J\"&T(!"
        $s11 = "#6k@t\"+gOR"
        $s12 = "#6k?T\"+L=O"
        $s13 = "VarFileInfo"
        $s14 = "IsComObject"
        $s15 = "get_Ordinal"
        $s16 = "#6k>5\"(VE4"
        $s17 = "#6k>A\"%iRo"
        $s18 = "#6k>a\"+(%K"
        $s19 = "#6k@(\"*=PD"
        $s20 = "ThreadStaticAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 278KB and
    4 of them
}
    
