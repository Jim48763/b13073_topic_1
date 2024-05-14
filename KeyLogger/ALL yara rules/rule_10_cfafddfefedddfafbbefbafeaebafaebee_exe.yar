rule cfafddfefedddfafbbefbafeaebafaebee_exe {
strings:
        $s1 = "get_ModuleName"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "get_Columns"
        $s5 = "L[`Kge53kJ?"
        $s6 = "_CorExeMain"
        $s7 = "VarFileInfo"
        $s8 = "ProductName"
        $s9 = "wP+Y'6W[bZ)"
        $s10 = "#o}x`!0{nT)"
        $s11 = "FileDescription"
        $s12 = "ResolveEventArgs"
        $s13 = "AssemblyTitleAttribute"
        $s14 = "Microsoft Corporation"
        $s15 = "set_TabIndex"
        $s16 = "KeyEventArgs"
        $s17 = "ColumnHeader"
        $s18 = "Dictionary`2"
        $s19 = "bGlzdFZpZXcx"
        $s20 = "Synchronized"
condition:
    uint16(0) == 0x5a4d and filesize < 430KB and
    4 of them
}
    
