rule ddeeecefaabeffcddaaffffc_exe {
strings:
        $s1 = "EnumerateFiles"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "GetProcessesByName"
        $s5 = "RuntimeFieldHandle"
        $s6 = "this contact email"
        $s7 = "System.Linq"
        $s8 = "ProductName"
        $s9 = "VarFileInfo"
        $s10 = "_CorExeMain"
        $s11 = "ComputeHash"
        $s12 = "AES_Decrypt"
        $s13 = "FromMinutes"
        $s14 = "pictureBox1"
        $s15 = "op_Equality"
        $s16 = "EncryptFile"
        $s17 = "set_MinimizeBox"
        $s18 = "FileDescription"
        $s19 = "Rasomware2.0.exe"
        $s20 = "InitializeComponent"
condition:
    uint16(0) == 0x5a4d and filesize < 829KB and
    4 of them
}
    
