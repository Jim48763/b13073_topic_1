rule ffdbfabafadbbbefcaf_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "spanish-guatemala"
        $s3 = "english-caribbean"
        $s4 = "GetEnvironmentStrings"
        $s5 = "Runtime Error!"
        $s6 = "invalid string position"
        $s7 = "GetConsoleOutputCP"
        $s8 = "VarFileInfo"
        $s9 = "LC_MONETARY"
        $s10 = "SetVolumeLabelW"
        $s11 = "english-jamaica"
        $s12 = "`local vftable'"
        $s13 = "_gekelberifin@8"
        $s14 = "spanish-venezuela"
        $s15 = "chinese-singapore"
        $s16 = "AFX_DIALOG_LAYOUT"
        $s17 = "SetThreadPriority"
        $s18 = "TerminateProcess"
        $s19 = "GetModuleHandleA"
        $s20 = "CreateJobObjectW"
condition:
    uint16(0) == 0x5a4d and filesize < 276KB and
    4 of them
}
    
