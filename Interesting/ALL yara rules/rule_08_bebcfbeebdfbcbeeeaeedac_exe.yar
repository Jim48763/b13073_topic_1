rule bebcfbeebdfbcbeeeaeedac_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "_CorExeMain"
        $s4 = "VarFileInfo"
        $s5 = "FileDescription"
        $s6 = "n para la compatibilidad"
        $s7 = "Form1_FormClosing"
        $s8 = "shutdown -r -t 00"
        $s9 = "InitializeComponent"
        $s10 = "set_TabIndex"
        $s11 = "GraphicsUnit"
        $s12 = "DialogResult"
        $s13 = "Synchronized"
        $s14 = "System.Resources"
        $s15 = "PerformLayout"
        $s16 = "    </application>"
        $s17 = "GeneratedCodeAttribute"
        $s18 = "set_InitialImage"
        $s19 = "defaultInstance"
        $s20 = "add_FormClosed"
condition:
    uint16(0) == 0x5a4d and filesize < 42KB and
    4 of them
}
    
