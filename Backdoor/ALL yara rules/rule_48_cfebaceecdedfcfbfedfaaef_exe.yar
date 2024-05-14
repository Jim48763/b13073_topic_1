rule cfebaceecdedfcfbfedfaaef_exe {
strings:
        $s1 = "SelectLeftByCharacter"
        $s2 = "ExtendSelectionLeft"
        $s3 = "SelectToPageUp"
        $s4 = "SelectUpByPage"
        $s5 = "]E=E@ETYfBU)zj"
        $s6 = "RuntimeHelpers"
        $s7 = "AreTransformsClean"
        $s8 = "get_CorrectionList"
        $s9 = "STAThreadAttribute"
        $s10 = "DesignerGeneratedAttribute"
        $s11 = "LastIndexOf"
        $s12 = "MsgBoxStyle"
        $s13 = "n8(i-\"l3;'"
        $s14 = "_CorExeMain"
        $s15 = "ProductName"
        $s16 = "VarFileInfo"
        $s17 = "ThreadStaticAttribute"
        $s18 = "FileDescription"
        $s19 = "IFormatProvider"
        $s20 = "ToggleNumbering"
condition:
    uint16(0) == 0x5a4d and filesize < 876KB and
    4 of them
}
    
