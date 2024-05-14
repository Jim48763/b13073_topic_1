rule cdbfdaaecbbadecbbccba_exe {
strings:
        $s1 = "txt_supplier_address"
        $s2 = "RuntimeHelpers"
        $s3 = "System.Data.Common"
        $s4 = "msClinicInfo_Click"
        $s5 = "STAThreadAttribute"
        $s6 = "op_Equality"
        $s7 = "j9k?i2eoya<"
        $s8 = "M0Z m7$la8|"
        $s9 = "_CorExeMain"
        $s10 = "UOZ 1ghsa8T"
        $s11 = "r:RIuT~lD5g"
        $s12 = "get_Columns"
        $s13 = "ProductName"
        $s14 = "pictureBox1"
        $s15 = "VarFileInfo"
        $s16 = "kVZ -7G&a8v"
        $s17 = "\"MZ A6vla8"
        $s18 = "u)Z iTG$a8W"
        $s19 = "Cancel_40px"
        $s20 = "ExecuteNonQuery"
condition:
    uint16(0) == 0x5a4d and filesize < 1096KB and
    4 of them
}
    
