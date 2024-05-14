rule bebdabafcaedcadebadfdfcaabef_exe {
strings:
        $s1 = "AutoPropertyValue"
        $s2 = "RuntimeHelpers"
        $s3 = "0hA|Q|'vBjOn^|"
        $s4 = "MakeDrawBitmap"
        $s5 = "AuthenticationMode"
        $s6 = "STAThreadAttribute"
        $s7 = "DesignerGeneratedAttribute"
        $s8 = "|.Zztg+R<1I"
        $s9 = "PictureBox1"
        $s10 = "U\"~M39v2EP"
        $s11 = "ProductName"
        $s12 = "R\"v'EP.Km~"
        $s13 = "_CorExeMain"
        $s14 = "(E)xit Game"
        $s15 = "VarFileInfo"
        $s16 = "d<rw%t2bA@L"
        $s17 = "*qlJ-{TtW29"
        $s18 = "ThreadStaticAttribute"
        $s19 = "FileDescription"
        $s20 = "set_MinimizeBox"
condition:
    uint16(0) == 0x5a4d and filesize < 927KB and
    4 of them
}
    
