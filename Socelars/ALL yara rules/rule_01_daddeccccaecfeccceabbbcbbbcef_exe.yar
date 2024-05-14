rule daddeccccaecfeccceabbbcbbbcef_exe {
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
        $s13 = "20383T<X<\\<`<p=t=x="
        $s14 = "too many columns in %s"
        $s15 = "executable format error"
        $s16 = "database %s is already in use"
        $s17 = "SeProfileSingleProcessPrivilege"
        $s18 = "result out of range"
        $s19 = "directory not empty"
        $s20 = "err : securepref not found"
condition:
    uint16(0) == 0x5a4d and filesize < 1423KB and
    4 of them
}
    
