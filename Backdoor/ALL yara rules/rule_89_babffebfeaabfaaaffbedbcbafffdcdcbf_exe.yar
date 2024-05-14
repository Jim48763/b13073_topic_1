rule babffebfeaabfaaaffbedbcbafffdcdcbf_exe {
strings:
        $s1 = "txt_supplier_address"
        $s2 = "RuntimeHelpers"
        $s3 = "System.Data.Common"
        $s4 = "msClinicInfo_Click"
        $s5 = "STAThreadAttribute"
        $s6 = "x/M#b>l*Q{m"
        $s7 = "op_Equality"
        $s8 = "j9k?i2eoya<"
        $s9 = "j!YZ -lwa8J"
        $s10 = "_CorExeMain"
        $s11 = "S34(p1%\"n)"
        $s12 = "get_Columns"
        $s13 = "ProductName"
        $s14 = "'zcZ dbP=a8"
        $s15 = "pictureBox1"
        $s16 = "VarFileInfo"
        $s17 = ")GZ 0?OWa8!"
        $s18 = "$Z \"mOXa8Q"
        $s19 = "s6Z C,}qa8d"
        $s20 = "OGnLk%gT(Kj"
condition:
    uint16(0) == 0x5a4d and filesize < 1085KB and
    4 of them
}
    
