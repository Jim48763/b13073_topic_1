rule ffbefecdcebefdaffeabaa_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "      version=\"6.0.0.0\""
        $s3 = "RegSetValueExW"
        $s4 = "LoadStringW"
        $s5 = "oCLHei?3K>w"
        $s6 = "=_jZ\"1Q&ng"
        $s7 = ":d`$f|\"4mv"
        $s8 = "d/vGsi.fhw4"
        $s9 = "o{gsA09Mf6]"
        $s10 = "6&cW\"!4<)v"
        $s11 = "YFPxA2COH;-"
        $s12 = ">A@|_kapDhY"
        $s13 = "0\"|.F1d<Oe"
        $s14 = "DPZ(*T-bHF,"
        $s15 = "DialogBoxParamW"
        $s16 = "ProgramFilesDir"
        $s17 = "`local vftable'"
        $s18 = "IsWindowVisible"
        $s19 = "DeviceIoControl"
        $s20 = "ARarHtmlClassName"
condition:
    uint16(0) == 0x5a4d and filesize < 1556KB and
    4 of them
}
    
