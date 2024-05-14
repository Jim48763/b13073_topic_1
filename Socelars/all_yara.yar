import pe
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
    
rule cbedceabecefcacbefddebc_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "/HS]<~h_>v#"
        $s5 = "|~lIJj0\"[2"
        $s6 = "d[ KS4l*)zL"
        $s7 = "Y;Ct~\"I*Vq"
        $s8 = "]2g.NrUuOnP"
        $s9 = "J`pl%N~V*-s"
        $s10 = "m:b5YC-9KXr"
        $s11 = "_tgukIe!2OF"
        $s12 = "(Frz_n2>#a7"
        $s13 = "-uCsYD=H%0N"
        $s14 = "n]P9:XG2~;r"
        $s15 = "}`50TSfI[Us"
        $s16 = "jEW=e-wM\"'"
        $s17 = "7U2KS\"-6 H"
        $s18 = "!l<~GVM/QXC"
        $s19 = "$[:^MhRbTO-"
        $s20 = "zF4gAi96f_J"
condition:
    uint16(0) == 0x5a4d and filesize < 3964KB and
    4 of them
}
    
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
    
rule dabaeafebcdcdcffffcefefd_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "executable format error"
        $s6 = "result out of range"
        $s7 = "directory not empty"
        $s8 = "err : securepref not found"
        $s9 = "CoInitializeEx"
        $s10 = "RegSetValueExA"
        $s11 = "invalid string position"
        $s12 = "invalid distance code"
        $s13 = "RtlNtStatusToDosError"
        $s14 = "operation canceled"
        $s15 = "/Home/Index/lkdinl"
        $s16 = "LC_MONETARY"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "DeviceIoControl"
        $s20 = "Process32FirstW"
condition:
    uint16(0) == 0x5a4d and filesize < 546KB and
    4 of them
}
    
rule fbffccdbafefadadaeefbacbda_exe {
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
    uint16(0) == 0x5a4d and filesize < 1421KB and
    4 of them
}
    