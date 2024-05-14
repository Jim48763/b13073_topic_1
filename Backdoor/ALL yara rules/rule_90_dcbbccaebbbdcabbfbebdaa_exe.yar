rule dcbbccaebbbdcabbfbebdaa_exe {
strings:
        $s1 = "<.ctor>b__20_3"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "e^.;NAT,o[u"
        $s5 = "_CorExeMain"
        $s6 = "SoundPlayer"
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "FileDescription"
        $s10 = "KeyEventHandler"
        $s11 = "set_FilterIndex"
        $s12 = "get_ClipRectangle"
        $s13 = "IndirectVecteur2D"
        $s14 = "InitializeComponent"
        $s15 = "Synchronized"
        $s16 = "System.Media"
        $s17 = "IAsyncResult"
        $s18 = "<Update>b__2"
        $s19 = "GraphicsUnit"
        $s20 = "DialogResult"
condition:
    uint16(0) == 0x5a4d and filesize < 583KB and
    4 of them
}
    
