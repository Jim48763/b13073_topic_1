rule ffbcedbaddbbbfeacaacebcd_exe {
strings:
        $s1 = "PartialExtensions"
        $s2 = "createTypeBuilder"
        $s3 = "AssemblyBuilderAccess"
        $s4 = "StoreOperationStageComponent"
        $s5 = "RuntimeHelpers"
        $s6 = "System.Data.Common"
        $s7 = "System.Linq"
        $s8 = "op_Equality"
        $s9 = "DisplayText"
        $s10 = "_CorExeMain"
        $s11 = "ComputeHash"
        $s12 = "-tBHjK\">Eh"
        $s13 = "b[Xftgw~dVW"
        $s14 = "IGrouping`2"
        $s15 = "IFormatProvider"
        $s16 = "PropertyBuilder"
        $s17 = "DataRowCollection"
        $s18 = "OrderByDescending"
        $s19 = "GetExpressionText"
        $s20 = "IMarkupFormatter"
condition:
    uint16(0) == 0x5a4d and filesize < 1001KB and
    4 of them
}
    
