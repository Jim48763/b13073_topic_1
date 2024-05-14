rule feeaaeaeeedfbcacdbacbcecddf_exe {
strings:
        $s1 = "Palatino Linotype"
        $s2 = "Add Selected File(s)"
        $s3 = "RegSetValueExA"
        $s4 = "28C4C820-401A-101B-A3C9-08002B2F49FB"
        $s5 = "__vbaLateMemCallLd"
        $s6 = "Save Archive As..."
        $s7 = "InsertByVal"
        $s8 = "|H)g]?M7x-J"
        $s9 = "EncryptFile"
        $s10 = "Version 5.2"
        $s11 = "TA|hofjband"
        $s12 = "VarFileInfo"
        $s13 = "5/>_v7RBUGW"
        $s14 = "File is Protected"
        $s15 = "GetComputerNameA"
        $s16 = "lblCopyright"
        $s17 = "Module32Next"
        $s18 = "Archiver 5.0"
        $s19 = "__vbaR8FixI4"
        $s20 = "__vbaPowerR8"
condition:
    uint16(0) == 0x5a4d and filesize < 742KB and
    4 of them
}
    
