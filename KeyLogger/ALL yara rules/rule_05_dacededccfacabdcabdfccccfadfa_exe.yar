rule dacededccfacabdcabdfccccfadfa_exe {
strings:
        $s1 = "<Decodu>b__9_1"
        $s2 = "RuntymeHelpers"
        $s3 = "cymmetricAlworithm"
        $s4 = "Comf{sibleA"
        $s5 = "~t|megypxHa"
        $s6 = "Sa-DBF.XTUK"
        $s7 = "YOException"
        $s8 = "_^o}DwlXatn"
        $s9 = "VarFileInfo"
        $s10 = "ProductName"
        $s11 = "}~czrpe9dwl"
        $s12 = "set_WintowStyle"
        $s13 = "n |n WOc3mowe. "
        $s14 = "FileDescription"
        $s15 = "ELoggerEventArgsJ"
        $s16 = "lpQpplication^ame"
        $s17 = "InitializeComponent"
        $s18 = "set_RedirestStandardO"
        $s19 = "AssemblyTitleAttribute"
        $s20 = "pac{ageCount"
condition:
    uint16(0) == 0x5a4d and filesize < 338KB and
    4 of them
}
    
