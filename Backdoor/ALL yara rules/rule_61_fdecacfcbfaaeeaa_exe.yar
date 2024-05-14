rule fdecacfcbfaaeeaa_exe {
strings:
        $s1 = "=wvvv{{{oPBBBBBBB00////.'''-*%%%"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "DesignerGeneratedAttribute"
        $s5 = "gu[+0p-G>28"
        $s6 = "_CorExeMain"
        $s7 = "+,/1ADKLQH'"
        $s8 = "ProductName"
        $s9 = "VarFileInfo"
        $s10 = "ThreadStaticAttribute"
        $s11 = "FileDescription"
        $s12 = "InitializeComponent"
        $s13 = "5phinwnu.jz4"
        $s14 = "IConvertible"
        $s15 = "cypm1zqm.win"
        $s16 = "uxdpyqfg.foh"
        $s17 = "pculj5bh.vmu"
        $s18 = "mgg3ichp.ze5"
        $s19 = "yt4gw3fg.eav"
        $s20 = "y12ouoec.hrg"
condition:
    uint16(0) == 0x5a4d and filesize < 857KB and
    4 of them
}
    
