rule bfedabbccabedfedabbbfacdcaeb_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "english-caribbean"
        $s3 = "`vector destructor iterator'"
        $s4 = "Votre logiciel est bien "
        $s5 = "CoInitializeEx"
        $s6 = "Runtime Error!"
        $s7 = "invalid string position"
        $s8 = "GetConsoleOutputCP"
        $s9 = "ser_recv(): read error: %s"
        $s10 = "Song Title:"
        $s11 = "ProductName"
        $s12 = "LC_MONETARY"
        $s13 = "VarFileInfo"
        $s14 = "JezikROmogu"
        $s15 = "Gekaufte Lizenz"
        $s16 = "DialogBoxParamA"
        $s17 = "How To Compare:"
        $s18 = "english-jamaica"
        $s19 = "`local vftable'"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 383KB and
    4 of them
}
    
