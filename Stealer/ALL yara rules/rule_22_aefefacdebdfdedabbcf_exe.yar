rule aefefacdebdfdedabbcf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "glock-crosshair-small"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = "'/7?GOW_gow"
        $s6 = "O jb'w_x#U/"
        $s7 = "_CorExeMain"
        $s8 = "r`@C\"Wn6bq"
        $s9 = "SoundPlayer"
        $s10 = "VY$Xby_eE,I"
        $s11 = "ProductName"
        $s12 = "PT (6pl1QH}"
        $s13 = "VarFileInfo"
        $s14 = "pictureBox1"
        $s15 = "Dqs0&\"CVPp"
        $s16 = "4BzqLmI*~ce"
        $s17 = "FileDescription"
        $s18 = "p:8\\1}p]948o;8-"
        $s19 = "InitializeComponent"
        $s20 = "get_FlatAppearance"
condition:
    uint16(0) == 0x5a4d and filesize < 1276KB and
    4 of them
}
    
