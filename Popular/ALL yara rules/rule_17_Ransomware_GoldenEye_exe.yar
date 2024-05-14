rule Ransomware_GoldenEye_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "SetDefaultDllDirectories"
        $s5 = ".bmp;*.dib;*.png;*.jpg;*.jpeg;*.jpe;*.jfif;*.gif)"
        $s6 = "RegSetValueExA"
        $s7 = "SetConsoleCtrlHandler"
        $s8 = "GIF (*.gif)"
        $s9 = "LC_MONETARY"
        $s10 = "PNG (*.png)"
        $s11 = "english-jamaica"
        $s12 = "`local vftable'"
        $s13 = "MagnifierWindow"
        $s14 = "IsWindowVisible"
        $s15 = "DialogBoxParamA"
        $s16 = "SetThreadPriority"
        $s17 = "All Picture Files"
        $s18 = "spanish-venezuela"
        $s19 = "ZoominSliderLevel"
        $s20 = "magnification.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 259KB and
    4 of them
}
    
