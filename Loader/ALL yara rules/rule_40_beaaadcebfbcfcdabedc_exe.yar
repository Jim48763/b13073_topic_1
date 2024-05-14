rule beaaadcebfbcfcdabedc_exe {
strings:
        $s1 = "ImmSetCompositionFontW"
        $s2 = "RegSetValueExW"
        $s3 = "GetModuleHandleA"
        $s4 = "acmFormatChooseW"
        $s5 = "midiOutClose"
        $s6 = "WINSPOOL.DRV"
        $s7 = "IsCharLowerA"
        $s8 = "InternetGetConnectedStateExW"
        $s9 = "SetActivePwrScheme"
        $s10 = "AssocQueryKeyW"
        $s11 = "GetTapePosition"
        $s12 = "B9EO~U{rVM"
        $s13 = "UrlCompareW"
        $s14 = "wvnsprintfA"
        $s15 = "PathAppendW"
        $s16 = "DrawTextExW"
        $s17 = "SetDlgItemTextW"
        $s18 = "JetSetColumn"
        $s19 = "KERNEL32.dll"
        $s20 = "DsGetDcNameW"
condition:
    uint16(0) == 0x5a4d and filesize < 221KB and
    4 of them
}
    
