rule Trojan_Anti_VM_ANA_exe {
strings:
        $s1 = "ALERT_VIRUS_NAMES"
        $s2 = "TreeViewEventArgs"
        $s3 = "GetEnvironmentStrings"
        $s4 = "EnableButtonsDelegate"
        $s5 = "DescriptionAttribute"
        $s6 = "ManagementBaseObject"
        $s7 = "set_SelectedImageIndex"
        $s8 = "SafariChromeFirefox"
        $s9 = "FlagsAttribute"
        $s10 = "Runtime Error!"
        $s11 = "SFGAO_VALIDATE"
        $s12 = "invalid string position"
        $s13 = "MarshalAsAttribute"
        $s14 = "InstallCertificate"
        $s15 = "SFGAO_CONTENTSMASK"
        $s16 = "STAThreadAttribute"
        $s17 = "VolumeSerialNumber"
        $s18 = "&X_f1Ay`QLp"
        $s19 = "LPx`/>h(;Di"
        $s20 = "('*vF<Xix~%"
condition:
    uint16(0) == 0x5a4d and filesize < 2128KB and
    4 of them
}
    
