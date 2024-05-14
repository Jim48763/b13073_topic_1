rule baccbcbeacbaeadbffdaefab_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "`vector destructor iterator'"
        $s3 = "Directory not empty"
        $s4 = "<file unknown>"
        $s5 = "invalid string position"
        $s6 = "No child processes"
        $s7 = "GetConsoleOutputCP"
        $s8 = "$;2}i\":A <"
        $s9 = "CopyFileExW"
        $s10 = ",CF~Qe=oBt("
        $s11 = "e:}SBXjTVn!"
        $s12 = "&\"(go9Zbi4"
        $s13 = "VarFileInfo"
        $s14 = "i<TvpxwAL-j"
        $s15 = "SetVolumeLabelA"
        $s16 = "telegumexoyihoz"
        $s17 = "`local vftable'"
        $s18 = "TerminateProcess"
        $s19 = "CreateJobObjectW"
        $s20 = "SetComputerNameA"
condition:
    uint16(0) == 0x5a4d and filesize < 836KB and
    4 of them
}
    
