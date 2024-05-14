rule beecccfbbaeadeaffdedfbebebfaaa_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "cross device link"
        $s4 = "last_insert_rowid"
        $s5 = "JetRetrieveColumn"
        $s6 = "CreateThreadpoolTimer"
        $s7 = "`vector destructor iterator'"
        $s8 = "onoffalseyestruextrafull"
        $s9 = " exceeds the maximum of "
        $s10 = "wrong # of entries in index "
        $s11 = "get_New_Edge_cookies"
        $s12 = "authorization denied"
        $s13 = "notification message"
        $s14 = " USING COVERING INDEX "
        $s15 = "executable format error"
        $s16 = "result out of range"
        $s17 = "directory not empty"
        $s18 = "invalid string position"
        $s19 = "On tree page %d cell %d: "
        $s20 = "ios_base::failbit set"
condition:
    uint16(0) == 0x5a4d and filesize < 1077KB and
    4 of them
}
    
