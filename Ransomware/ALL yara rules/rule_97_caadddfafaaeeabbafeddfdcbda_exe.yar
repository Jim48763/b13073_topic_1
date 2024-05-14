rule caadddfafaaeeabbafeddfdcbda_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "Directory not empty"
        $s5 = "invalid string position"
        $s6 = "No child processes"
        $s7 = "W:|<EGr^umf"
        $s8 = "Xg1osnK]}`r"
        $s9 = "} UPQpBw\"$"
        $s10 = "b(VDj,Q$@d7"
        $s11 = "LC_MONETARY"
        $s12 = "Np>r<eREu2L"
        $s13 = "english-jamaica"
        $s14 = "`local vftable'"
        $s15 = "spanish-venezuela"
        $s16 = "Dialog Box: Modal"
        $s17 = "AFX_DIALOG_LAYOUT"
        $s18 = "SetComputerNameW"
        $s19 = "TerminateProcess"
        $s20 = "GetModuleHandleW"
condition:
    uint16(0) == 0x5a4d and filesize < 784KB and
    4 of them
}
    
