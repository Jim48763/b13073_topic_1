rule baafcbbacedbcdfdadeaacdd_exe {
strings:
        $s1 = "  <!-- Wskazuje, "
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "RuntimeFieldHandle"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "ComputeHash"
        $s9 = "AES_Decrypt"
        $s10 = "op_Equality"
        $s11 = "EncryptFile"
        $s12 = "set_WindowState"
        $s13 = "set_MinimizeBox"
        $s14 = "BlackMamba2.exe"
        $s15 = "FileDescription"
        $s16 = "set_RightToLeft"
        $s17 = "Form1_FormClosing"
        $s18 = "set_AutoSizeMode"
        $s19 = "InitializeComponent"
        $s20 = "tmr_start_enc_Tick"
condition:
    uint16(0) == 0x5a4d and filesize < 150KB and
    4 of them
}
    
