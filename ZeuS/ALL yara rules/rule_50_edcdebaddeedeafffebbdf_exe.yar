rule edcdebaddeedeafffebbdf_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "`vector destructor iterator'"
        $s3 = "BcImages.MainImages"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "GetConsoleOutputCP"
        $s7 = "TUiCheckBox"
        $s8 = "ProductName"
        $s9 = "LC_MONETARY"
        $s10 = " </rdf:RDF>"
        $s11 = "VarFileInfo"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "FileDescription"
        $s15 = "spanish-venezuela"
        $s16 = "chinese-singapore"
        $s17 = "TerminateProcess"
        $s18 = "GetModuleHandleW"
        $s19 = "DispatchMessageA"
        $s20 = "&Always close all tabs"
condition:
    uint16(0) == 0x5a4d and filesize < 391KB and
    4 of them
}
    
