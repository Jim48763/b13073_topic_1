rule aaebbbbbddecacdbddcdadb_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "EnumerateFiles"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = "System.Linq"
        $s6 = "ProductName"
        $s7 = "_CorExeMain"
        $s8 = "ComputeHash"
        $s9 = "pictureBox2"
        $s10 = "AES_Decrypt"
        $s11 = "op_Equality"
        $s12 = "FromMinutes"
        $s13 = "get_ProcessName"
        $s14 = "set_MinimizeBox"
        $s15 = "FileDescription"
        $s16 = "Rasomware2.0.exe"
        $s17 = "InitializeComponent"
        $s18 = "AssemblyTitleAttribute"
        $s19 = "The key is correct"
        $s20 = "GraphicsUnit"
condition:
    uint16(0) == 0x5a4d and filesize < 505KB and
    4 of them
}
    
