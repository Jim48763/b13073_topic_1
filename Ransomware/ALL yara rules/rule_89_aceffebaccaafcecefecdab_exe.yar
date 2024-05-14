rule aceffebaccaafcecefecdab_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "My.WebServices"
        $s3 = "STAThreadAttribute"
        $s4 = "AuthenticationMode"
        $s5 = "RuntimeFieldHandle"
        $s6 = "ProductName"
        $s7 = "_CorExeMain"
        $s8 = "ComputeHash"
        $s9 = "p;@9n$sUCO:"
        $s10 = "PictureBox1"
        $s11 = "op_Equality"
        $s12 = "ThreadStaticAttribute"
        $s13 = "IsWindowVisible"
        $s14 = "set_WindowState"
        $s15 = "FileDescription"
        $s16 = "get_MachineName"
        $s17 = "get_ProcessName"
        $s18 = "ResolveEventArgs"
        $s19 = "GraphicsUnit"
        $s20 = "set_TabIndex"
condition:
    uint16(0) == 0x5a4d and filesize < 361KB and
    4 of them
}
    
