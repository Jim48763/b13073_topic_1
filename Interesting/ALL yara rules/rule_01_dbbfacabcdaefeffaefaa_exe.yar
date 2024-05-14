rule dbbfacabcdaefeffaefaa_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "GetWindowDC"
        $s3 = "[bwGS1M'}4 "
        $s4 = "Me)L$*1|]mG"
        $s5 = "24MC,.Km(+I"
        $s6 = "_CorExeMain"
        $s7 = "VarFileInfo"
        $s8 = "13M*,.KQ)+I"
        $s9 = "ProductName"
        $s10 = "13P&+-Mq(*K"
        $s11 = "_initialize_narrow_environment"
        $s12 = "FileDescription"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleW"
        $s15 = "m reconhecimento autom"
        $s16 = " automaticamente o ambiente mais compat"
        $s17 = "InitializeComponent"
        $s18 = "AssemblyTitleAttribute"
        $s19 = "GetCurrentThreadId"
        $s20 = "0eaJ0&C\"PL`"
condition:
    uint16(0) == 0x5a4d and filesize < 653KB and
    4 of them
}
    
