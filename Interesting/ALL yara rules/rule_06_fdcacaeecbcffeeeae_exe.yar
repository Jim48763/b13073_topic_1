rule fdcacaeecbcffeeeae_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "13P&+-Mq(*K"
        $s4 = "24MC,.Km(+I"
        $s5 = "_CorExeMain"
        $s6 = "Me)L$*1|]mG"
        $s7 = "VarFileInfo"
        $s8 = "13M*,.KQ)+I"
        $s9 = "FileDescription"
        $s10 = "m reconhecimento autom"
        $s11 = " automaticamente o ambiente mais compat"
        $s12 = "InitializeComponent"
        $s13 = "0eaJ0&C\"PL`"
        $s14 = "B~VqDkG$JzPV"
        $s15 = "Synchronized"
        $s16 = "    </application>"
        $s17 = "GeneratedCodeAttribute"
        $s18 = "clr-namespace:eye"
        $s19 = "eye.MainWindow"
        $s20 = "eye.Properties.Resources"
condition:
    uint16(0) == 0x5a4d and filesize < 779KB and
    4 of them
}
    
