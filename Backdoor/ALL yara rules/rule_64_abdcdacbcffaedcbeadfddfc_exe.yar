rule abdcdacbcffaedcbeadfddfc_exe {
strings:
        $s1 = "$this.GridSize"
        $s2 = "CSharpCodeProvider"
        $s3 = "BitConverterActivationContext"
        $s4 = "w_{c+xG1U!D"
        $s5 = "[XZ8^]}%~NT"
        $s6 = "_CorExeMain"
        $s7 = "#psScyZKYi["
        $s8 = "ProductName"
        $s9 = "VarFileInfo"
        $s10 = "FileDescription"
        $s11 = "OrdinalComparer"
        $s12 = "customCultureName"
        $s13 = "set_GenerateExecutable"
        $s14 = "DelegateBindingFlags"
        $s15 = "set_GenerateInMemory"
        $s16 = "numberGroupSeparator"
        $s17 = "CompilerParameters"
        $s18 = "dateTimeInfo"
        $s19 = "IAsyncResult"
        $s20 = "*>d~Un~#e%{$"
condition:
    uint16(0) == 0x5a4d and filesize < 707KB and
    4 of them
}
    
