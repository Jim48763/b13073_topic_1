rule eabeafffdebecebedecfdbcbd_exe {
strings:
        $s1 = "set_usernameField"
        $s2 = "IPInterfaceProperties"
        $s3 = "AShkAhRk7ecZQhBAkYD"
        $s4 = "LicenseAcceptedRadio"
        $s5 = "ManagementBaseObject"
        $s6 = "get_BatteryLifePercent"
        $s7 = "set_ForegroundColor"
        $s8 = "FormatFirstLetterUpperCase"
        $s9 = "FlagsAttribute"
        $s10 = "RuntimeHelpers"
        $s11 = "SetConsoleCtrlHandler"
        $s12 = "LastIndexOf"
        $s13 = "My Pictures"
        $s14 = "]i~k|38F9&f"
        $s15 = "DecryptBlob"
        $s16 = "ProductName"
        $s17 = "Loqp1sx/[Q{"
        $s18 = "[m4,yz*PNeR"
        $s19 = ">pKmFNbT$0-"
        $s20 = "JuPSR_forms"
condition:
    uint16(0) == 0x5a4d and filesize < 3650KB and
    4 of them
}
    
