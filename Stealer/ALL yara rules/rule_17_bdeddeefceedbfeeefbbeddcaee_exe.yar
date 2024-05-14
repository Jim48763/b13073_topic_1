rule bdeddeefceedbfeeefbbeddcaee_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "RuntimeHelpers"
        $s3 = "System.Data.Common"
        $s4 = "RuntimeFieldHandle"
        $s5 = "Select User First."
        $s6 = "STAThreadAttribute"
        $s7 = "get_Columns"
        $s8 = "_CorExeMain"
        $s9 = "ExecuteNonQuery"
        $s10 = "DataRowCollection"
        $s11 = "get_DarkSlateGray"
        $s12 = "ConfigurationManager"
        $s13 = "DEPARTMENT STORE MANAGEMENT SYSTEM"
        $s14 = "InitializeComponent"
        $s15 = "get_Discount"
        $s16 = "Synchronized"
        $s17 = "AddWithValue"
        $s18 = "InventoryDAL"
        $s19 = "DialogResult"
        $s20 = "set_ReadOnly"
condition:
    uint16(0) == 0x5a4d and filesize < 226KB and
    4 of them
}
    
