rule dbdbbcfeadfadaebddeed_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "EVariantDispatchError"
        $s3 = "TInterfacedPersistent"
        $s4 = "EVariantBadVarTypeError"
        $s5 = "GetSystemPowerStatus"
        $s6 = "ImmSetCompositionFontA"
        $s7 = "GetEnhMetaFilePaletteEntries"
        $s8 = "Unknown compression"
        $s9 = "ERR|Socket error..|"
        $s10 = " 2001, 2002 Mike Lischke"
        $s11 = "VirtualAllocEx"
        $s12 = "UntActivePorts"
        $s13 = "TShortCutList8"
        $s14 = "ckRunningOrNew"
        $s15 = "RegSetValueExA"
        $s16 = "OnMouseWheelUp"
        $s17 = "GetWindowTheme"
        $s18 = "set cdAudio door open"
        $s19 = "TWinControlActionLink"
        $s20 = "CoCreateInstanceEx"
condition:
    uint16(0) == 0x5a4d and filesize < 663KB and
    4 of them
}
    
