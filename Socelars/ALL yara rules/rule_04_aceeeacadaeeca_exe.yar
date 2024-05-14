rule aceeeacadaeeca_exe {
strings:
        $s1 = "last_insert_rowid"
        $s2 = "spanish-guatemala"
        $s3 = "\"accountinfo\":{"
        $s4 = "cross device link"
        $s5 = "german-luxembourg"
        $s6 = "english-caribbean"
        $s7 = "onoffalseyestruextrafull"
        $s8 = "My local test also works"
        $s9 = "http\\shell\\open\\command"
        $s10 = "wrong # of entries in index "
        $s11 = "InternetGetCookieExA"
        $s12 = "authorization denied"
        $s13 = "too many columns in %s"
        $s14 = "executable format error"
        $s15 = "database %s is already in use"
        $s16 = "SeProfileSingleProcessPrivilege"
        $s17 = "0%0J0V0O2m2r2'4}4*5"
        $s18 = "result out of range"
        $s19 = "directory not empty"
        $s20 = "err : securepref not found"
condition:
    uint16(0) == 0x5a4d and filesize < 1465KB and
    4 of them
}
    
