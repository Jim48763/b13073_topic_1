rule affaaaaebdadaabddcfeffdaebaabb_exe {
strings:
        $s1 = "set_SplitterDistance"
        $s2 = "RuntimeHelpers"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = "ProductName"
        $s6 = "JF? HD>pGC<"
        $s7 = "_CorExeMain"
        $s8 = "fmZ J9!_a8v"
        $s9 = "EA: D@9pC?8"
        $s10 = "KGA IF?pHD="
        $s11 = "VarFileInfo"
        $s12 = "SPI QNGpOKE"
        $s13 = "YUO VSMpTQJ"
        $s14 = "op_Equality"
        $s15 = "FileDescription"
        $s16 = "InitializeComponent"
        $s17 = "AssemblyTitleAttribute"
        $s18 = "SubstractInstruction"
        $s19 = "set_TabIndex"
        $s20 = "Synchronized"
condition:
    uint16(0) == 0x5a4d and filesize < 434KB and
    4 of them
}
    
