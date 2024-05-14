rule cbdcbfbcbaeadffaddcfccafba_exe {
strings:
        $s1 = "last_insert_rowid"
        $s2 = "GetEnvironmentStrings"
        $s3 = "`vector destructor iterator'"
        $s4 = "x-ebcdic-koreanandkoreanextended"
        $s5 = "wrong # of entries in index "
        $s6 = "authorization denied"
        $s7 = " USING COVERING INDEX "
        $s8 = "x-ebcdic-icelandic-euro"
        $s9 = "invalid string position"
        $s10 = "On tree page %d cell %d: "
        $s11 = "database is locked"
        $s12 = "GetConsoleOutputCP"
        $s13 = "6d718e:W;f>"
        $s14 = "_a23cdefghi"
        $s15 = "tbl_name=%Q"
        $s16 = "local time unavailable"
        $s17 = "`local vftable'"
        $s18 = "no query solution"
        $s19 = "cannot commit - no transaction is active"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 1052KB and
    4 of them
}
    
