rule efbbadbcdeecaeffcbebccfbdcca_exe {
strings:
        $s1 = "System.Data.OleDb"
        $s2 = "Network_Printer.txt"
        $s3 = "RuntimeHelpers"
        $s4 = "STAThreadAttribute"
        $s5 = "DesignerGeneratedAttribute"
        $s6 = "mflgIsDirty"
        $s7 = "My.Computer"
        $s8 = "IOException"
        $s9 = "MsgBoxStyle"
        $s10 = "_CorExeMain"
        $s11 = "get_Columns"
        $s12 = "#(`*iv/Y9jz"
        $s13 = "ProductName"
        $s14 = "First Name:"
        $s15 = "VarFileInfo"
        $s16 = "ThreadStaticAttribute"
        $s17 = "ExecuteNonQuery"
        $s18 = "FileDescription"
        $s19 = "m_enumDVDFormat"
        $s20 = "FirstWeekOfYear"
condition:
    uint16(0) == 0x5a4d and filesize < 459KB and
    4 of them
}
    
