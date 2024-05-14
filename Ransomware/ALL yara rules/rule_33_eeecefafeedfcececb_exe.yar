rule eeecefafeedfcececb_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "RuntimeFieldHandle"
        $s4 = "VarFileInfo"
        $s5 = "ProductName"
        $s6 = "_CorExeMain"
        $s7 = "ComputeHash"
        $s8 = "EncryptFile"
        $s9 = "get_MachineName"
        $s10 = "FileDescription"
        $s11 = "InitializeComponent"
        $s12 = "Synchronized"
        $s13 = "System.Resources"
        $s14 = "StringBuilder"
        $s15 = "GeneratedCodeAttribute"
        $s16 = "    </security>"
        $s17 = "defaultInstance"
        $s18 = "passwordBytes"
        $s19 = "YOURPASSWORDHERE"
        $s20 = "$$method0x6000008-1"
condition:
    uint16(0) == 0x5a4d and filesize < 212KB and
    4 of them
}
    
