rule Ransomware_Jigsaw_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "All you have to do..."
        $s3 = "BitcoinBlackmailer"
        $s4 = "RuntimeFieldHandle"
        $s5 = "ImposeRestrictions"
        $s6 = "STAThreadAttribute"
        $s7 = "GetProcessesByName"
        $s8 = "ReadFromEmbeddedResources"
        $s9 = "System.Linq"
        $s10 = "ProductName"
        $s11 = "_CorExeMain"
        $s12 = "op_Equality"
        $s13 = "AssemblyVersion"
        $s14 = "set_MinimizeBox"
        $s15 = "IFormatProvider"
        $s16 = "FileDescription"
        $s17 = "ResolveEventArgs"
        $s18 = "InitializeComponent"
        $s19 = "AssemblyTitleAttribute"
        $s20 = "GraphicsUnit"
condition:
    uint16(0) == 0x5a4d and filesize < 288KB and
    4 of them
}
    
