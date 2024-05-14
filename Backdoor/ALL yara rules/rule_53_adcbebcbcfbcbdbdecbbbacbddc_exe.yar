rule adcbebcbcfbcbdbdecbbbacbddc_exe {
strings:
        $s1 = "XmlSchemaParticle"
        $s2 = "set_MainMenuStrip"
        $s3 = "GetSchemaSerializable"
        $s4 = "ToolboxItemAttribute"
        $s5 = "set_FixedValue"
        $s6 = "GetTypedDataSetSchema"
        $s7 = "System.Data.Common"
        $s8 = "STAThreadAttribute"
        $s9 = "hRQbDziEVvG"
        $s10 = "_CorExeMain"
        $s11 = "Author_Name"
        $s12 = "get_Columns"
        $s13 = "ProductName"
        $s14 = "TouchSystem"
        $s15 = "VarFileInfo"
        $s16 = "DefaultMemberAttribute"
        $s17 = "ExecuteNonQuery"
        $s18 = "frmSanPham_Load"
        $s19 = "set_MinimizeBox"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 377KB and
    4 of them
}
    
