rule dbdebecfdaadcbaefbf_exe {
strings:
        $s1 = "set_TransparencyKey"
        $s2 = "EnterDebugMode"
        $s3 = "GetProcessesByName"
        $s4 = "BreakOnTermination"
        $s5 = "STAThreadAttribute"
        $s6 = "pictureBox8"
        $s7 = "sound_file2"
        $s8 = "op_Equality"
        $s9 = "HT|x%=~M}ZO"
        $s10 = "Anti-Po0p3r"
        $s11 = "_CorExeMain"
        $s12 = "VarFileInfo"
        $s13 = "ProductName"
        $s14 = "set_WindowState"
        $s15 = "set_MinimizeBox"
        $s16 = "FileDescription"
        $s17 = "Clutt.Properties"
        $s18 = "InitializeComponent"
        $s19 = "AssemblyTitleAttribute"
        $s20 = "next_payload"
condition:
    uint16(0) == 0x5a4d and filesize < 1853KB and
    4 of them
}
    
