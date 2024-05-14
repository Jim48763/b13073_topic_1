rule addcdcdfcadeebcaedfdb_exe {
strings:
        $s1 = "q2ox3BQnB3YqLB1D3C3"
        $s2 = "i9yBT1JJKTgiwmlg9li"
        $s3 = "RuntimeHelpers"
        $s4 = "STAThreadAttribute"
        $s5 = "OWuRXxTmQhrTRumQKR"
        $s6 = "DesignerGeneratedAttribute"
        $s7 = "ProductName"
        $s8 = "_CorExeMain"
        $s9 = "VarFileInfo"
        $s10 = "ThreadStaticAttribute"
        $s11 = "FileDescription"
        $s12 = "XaaakonmnoiUVOvZ"
        $s13 = "hxUMWXUTUcVXdyMo"
        $s14 = "gHhUFnFNoFUcyHLJ"
        $s15 = "DebuggerHiddenAttribute"
        $s16 = "GPHVmZIWmbGKgZbWXZPP"
        $s17 = "InitializeComponent"
        $s18 = "set_TabIndex"
        $s19 = "Synchronized"
        $s20 = "get_Commands"
condition:
    uint16(0) == 0x5a4d and filesize < 366KB and
    4 of them
}
    
