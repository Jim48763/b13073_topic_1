rule dcfddffeefeaafccddedcdbcd_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "a\":z`K{F/*"
        $s4 = "9g]Hp06L<v;"
        $s5 = "_CorExeMain"
        $s6 = "VarFileInfo"
        $s7 = "ProductName"
        $s8 = "ThreadStaticAttribute"
        $s9 = "FileDescription"
        $s10 = "GetExportedTypes"
        $s11 = "fwkbpmakwlazbzkwpwwoieejw"
        $s12 = "InitializeComponent"
        $s13 = "AssemblyTitleAttribute"
        $s14 = "Qamecaeliconezhopeli"
        $s15 = "Synchronized"
        $s16 = "IAsyncResult"
        $s17 = "System.Resources"
        $s18 = "StringBuilder"
        $s19 = "GeneratedCodeAttribute"
        $s20 = "EncryptedBytes"
condition:
    uint16(0) == 0x5a4d and filesize < 703KB and
    4 of them
}
    
