rule febeeeedfdeadecddaaffeec_exe {
strings:
        $s1 = "AssemblyBuilderAccess"
        $s2 = "ManagementBaseObject"
        $s3 = "FlagsAttribute"
        $s4 = "get_ModuleName"
        $s5 = "RuntimeHelpers"
        $s6 = "GetProcessesByName"
        $s7 = "PixelFormat"
        $s8 = "F&XSIHRMKAP"
        $s9 = "IOException"
        $s10 = "VarFileInfo"
        $s11 = "ProductName"
        $s12 = "IFormatProvider"
        $s13 = "FileDescription"
        $s14 = "8e0f7a12-bfb=5fe"
        $s15 = "InitializeComponent"
        $s16 = "AssemblyTitleAttribute"
        $s17 = "ImageToBytes"
        $s18 = "IEquatable`1"
        $s19 = "yToken=b77a5"
        $s20 = "DialogResult"
condition:
    uint16(0) == 0x5a4d and filesize < 321KB and
    4 of them
}
    
