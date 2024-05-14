rule daddbeabcbfceebcccaaeffc_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "msctls_progress32"
        $s3 = "TMeasureItemEvent"
        $s4 = "COFREEUNUSEDLIBRARIES"
        $s5 = "UNREGISTERTYPELIBRARY"
        $s6 = "Unknown constant \"%s\""
        $s7 = "Network monitoring software from Paessler AG                "
        $s8 = "EndOffset range exceeded"
        $s9 = "Unable to insert an item"
        $s10 = "SetDefaultDllDirectories"
        $s11 = "'%s' is not a valid date"
        $s12 = "LicenseAcceptedRadio"
        $s13 = "hcessheProhinathTerm"
        $s14 = "ECompressInternalError"
        $s15 = "RemoveFontResourceA"
        $s16 = "utUserDefined:"
        $s17 = "RegSetValueExA"
        $s18 = "SetWindowTheme"
        $s19 = "ChangeResource"
        $s20 = "SetConsoleCtrlHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 2555KB and
    4 of them
}
    
