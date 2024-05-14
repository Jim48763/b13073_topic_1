rule bfbcbaceeafbfedaefedadad_exe {
strings:
        $s1 = "User Registration"
        $s2 = "TreeViewEventArgs"
        $s3 = "set_SplitterDistance"
        $s4 = "set_TransparencyKey"
        $s5 = "My.WebServices"
        $s6 = "RuntimeHelpers"
        $s7 = "System.Data.Common"
        $s8 = "Available Services"
        $s9 = "STAThreadAttribute"
        $s10 = "AuthenticationMode"
        $s11 = "DesignerGeneratedAttribute"
        $s12 = "-Lrwqtvmaop"
        $s13 = "9q>lj-b}xQP"
        $s14 = ")B\"L'(@#D+"
        $s15 = "System Info"
        $s16 = "Ynuq~JE}yp+"
        $s17 = " vq~pYI_<aZ"
        $s18 = "get_Columns"
        $s19 = "Slot Number"
        $s20 = "<zwt2-K9]WG"
condition:
    uint16(0) == 0x5a4d and filesize < 892KB and
    4 of them
}
    
