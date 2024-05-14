rule ecbcccafadcbdefdfccdabebb_exe {
strings:
        $s1 = "System.Data.OleDb"
        $s2 = "Network_Printer.txt"
        $s3 = "RuntimeHelpers"
        $s4 = "STAThreadAttribute"
        $s5 = "DesignerGeneratedAttribute"
        $s6 = "My.Computer"
        $s7 = "IOException"
        $s8 = "MsgBoxStyle"
        $s9 = "_CorExeMain"
        $s10 = "get_Columns"
        $s11 = "ProductName"
        $s12 = "First Name:"
        $s13 = "VarFileInfo"
        $s14 = "lW3hP}4p$xF"
        $s15 = "ThreadStaticAttribute"
        $s16 = "ExecuteNonQuery"
        $s17 = "FileDescription"
        $s18 = "FirstWeekOfYear"
        $s19 = "get_fnameTextBox"
        $s20 = "birthdateTextBox"
condition:
    uint16(0) == 0x5a4d and filesize < 554KB and
    4 of them
}
    
