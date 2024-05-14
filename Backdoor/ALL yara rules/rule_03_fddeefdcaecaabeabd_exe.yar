rule fddeefdcaecaabeabd_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "All Goods are at Net Cost"
        $s3 = "SetInvoiceHead"
        $s4 = "System.Data.Common"
        $s5 = "STAThreadAttribute"
        $s6 = "op_Equality"
        $s7 = "_CorExeMain"
        $s8 = "pictureBox1"
        $s9 = "VarFileInfo"
        $s10 = "pz>#BMH|,xO"
        $s11 = "ReadInvoiceData"
        $s12 = "ExecuteNonQuery"
        $s13 = "get_DefaultView"
        $s14 = "dateTimePicker2"
        $s15 = "FileDescription"
        $s16 = "Contact Details"
        $s17 = "Please Select Party Name"
        $s18 = "Edit Item Details"
        $s19 = "Select Challan No"
        $s20 = "ToShortDateString"
condition:
    uint16(0) == 0x5a4d and filesize < 555KB and
    4 of them
}
    
