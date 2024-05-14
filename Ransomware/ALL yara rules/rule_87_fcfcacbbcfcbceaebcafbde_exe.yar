rule fcfcacbbcfcbceaebcafbde_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "_CorExeMain"
        $s5 = "P;#/\"'4|7B"
        $s6 = "FileDescription"
        $s7 = "m reconhecimento autom"
        $s8 = " automaticamente o ambiente mais compat"
        $s9 = "InitializeComponent"
        $s10 = "Synchronized"
        $s11 = "System.Resources"
        $s12 = "    </application>"
        $s13 = "GeneratedCodeAttribute"
        $s14 = "clown.g.resources"
        $s15 = "    </security>"
        $s16 = "defaultInstance"
        $s17 = "set_StartupUri"
        $s18 = "DebuggingModes"
        $s19 = "LegalTrademarks"
        $s20 = "o precisam"
condition:
    uint16(0) == 0x5a4d and filesize < 185KB and
    4 of them
}
    
