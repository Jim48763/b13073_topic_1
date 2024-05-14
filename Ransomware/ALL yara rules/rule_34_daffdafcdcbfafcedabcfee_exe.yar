rule daffdafcdcbfafcedabcfee_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "RuntimeFieldHandle"
        $s4 = "VarFileInfo"
        $s5 = "ProductName"
        $s6 = "_CorExeMain"
        $s7 = "ComputeHash"
        $s8 = "get_MachineName"
        $s9 = "FileDescription"
        $s10 = "InitializeComponent"
        $s11 = "http://176.119.28.97/"
        $s12 = "ssvchost.Properties.Resources.resources"
        $s13 = "Synchronized"
        $s14 = "computerInfo"
        $s15 = "ssvchost.Properties"
        $s16 = "System.Resources"
        $s17 = "FromXmlString"
        $s18 = "StringBuilder"
        $s19 = "/C choice /C Y /N /D Y /T 5 & DEL "
        $s20 = "GeneratedCodeAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 23KB and
    4 of them
}
    
