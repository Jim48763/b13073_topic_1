rule cdffaedebbcbfafbadbcfdad_exe {
strings:
        $s1 = "DataRowExtensions"
        $s2 = "Inventory Reports"
        $s3 = "', `ContactNo` ='"
        $s4 = "All fields are required."
        $s5 = "txtDatePublish"
        $s6 = "RuntimeHelpers"
        $s7 = "4.94.34121 (Free) "
        $s8 = "System.Data.Common"
        $s9 = "STAThreadAttribute"
        $s10 = "Publisher :"
        $s11 = "ProductName"
        $s12 = "$%Ee^hv5+1#"
        $s13 = "(Eq\"-)ByIR"
        $s14 = "_CorExeMain"
        $s15 = "VarFileInfo"
        $s16 = "G/5-^k)hYM%"
        $s17 = "q/jU5f&3tXm"
        $s18 = "PictureBox1"
        $s19 = "NumbersOnly"
        $s20 = "igJV:q>zfl="
condition:
    uint16(0) == 0x5a4d and filesize < 1793KB and
    4 of them
}
    
