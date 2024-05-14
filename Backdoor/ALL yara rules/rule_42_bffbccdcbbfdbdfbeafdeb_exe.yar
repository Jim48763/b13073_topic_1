rule bffbccdcbbfdbdfbeafdeb_exe {
strings:
        $s1 = "<dir_ques>5__1"
        $s2 = "RuntimeHelpers"
        $s3 = "get_ReceiveBufferSize"
        $s4 = "<add_up_files>d__0"
        $s5 = "STAThreadAttribute"
        $s6 = "ProductName"
        $s7 = "PixelFormat"
        $s8 = "main_socket"
        $s9 = "_CorExeMain"
        $s10 = "get_MachineName"
        $s11 = "FileDescription"
        $s12 = "get_ProcessName"
        $s13 = "GetDirectoryName"
        $s14 = "DebuggerHiddenAttribute"
        $s15 = "AssemblyCultureAttribute"
        $s16 = "InitializeComponent"
        $s17 = "Synchronized"
        $s18 = "set_TabIndex"
        $s19 = "set_ShowIcon"
        $s20 = "lookup_drive"
condition:
    uint16(0) == 0x5a4d and filesize < 11553KB and
    4 of them
}
    
