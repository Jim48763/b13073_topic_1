rule dcadbfcadcbcaadfaebeadcbafb_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "You ran out of time!"
        $s3 = "set_TransparentColor"
        $s4 = "Please enter only one character"
        $s5 = "ii4lTCMJgQpJp99o4CC"
        $s6 = "hGBK0mYJZKwGIJwYZwv"
        $s7 = "RuntimeHelpers"
        $s8 = "My.WebServices"
        $s9 = "Challenge Selector"
        $s10 = "STAThreadAttribute"
        $s11 = "AuthenticationMode"
        $s12 = "DesignerGeneratedAttribute"
        $s13 = "My.Computer"
        $s14 = "PictureBox1"
        $s15 = "MsgBoxStyle"
        $s16 = "_CorExeMain"
        $s17 = "lstWordBank"
        $s18 = "c?3^a7u@O$>"
        $s19 = "ProductName"
        $s20 = "VarFileInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 624KB and
    4 of them
}
    
