rule decedbdffccedabcaceb_exe {
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
        $s17 = "result out of range"
        $s18 = "directory not empty"
        $s19 = "err : securepref not found"
        $s20 = "invalid string position"
condition:
    uint16(0) == 0x5a4d and filesize < 1420KB and
    4 of them
}
    
