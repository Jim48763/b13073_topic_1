rule cefbeeefafccdafaccfebebd_exe {
strings:
        $s1 = "DescriptionAttribute"
        $s2 = "ToolboxItemAttribute"
        $s3 = "DataGridViewPaintParts"
        $s4 = "get_ColorTypeConverter"
        $s5 = "get_SupportsSorting"
        $s6 = "RuntimeHelpers"
        $s7 = "get_InheritedStyle"
        $s8 = "RuntimeFieldHandle"
        $s9 = "STAThreadAttribute"
        $s10 = "DesignerGeneratedAttribute"
        $s11 = "ProductName"
        $s12 = "L6zZ V5iRa+"
        $s13 = "`KmY6]\"fC^"
        $s14 = "_CorExeMain"
        $s15 = "VarFileInfo"
        $s16 = "cr&Z 5K70a+"
        $s17 = "op_Equality"
        $s18 = "ThreadStaticAttribute"
        $s19 = "set_MinimizeBox"
        $s20 = "OrderedDictionary"
condition:
    uint16(0) == 0x5a4d and filesize < 626KB and
    4 of them
}
    
