rule aefddafdedeffdcdcdfdbf_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "GetEnvironmentStrings"
        $s5 = "Create a new document"
        $s6 = "Find the specified text"
        $s7 = "RegSetValueExA"
        $s8 = "invalid string position"
        $s9 = "accDoDefaultAction"
        $s10 = "GetConsoleOutputCP"
        $s11 = "Activate Task List"
        $s12 = "ProductName"
        $s13 = "eR}nQ]EkYAB"
        $s14 = "VarFileInfo"
        $s15 = "ULDV`pd+WaP"
        $s16 = "LC_MONETARY"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "IsWindowVisible"
        $s20 = "spanish-venezuela"
condition:
    uint16(0) == 0x5a4d and filesize < 487KB and
    4 of them
}
    
