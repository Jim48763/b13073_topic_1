rule bdaecbeafabbdafdbcfcadfabf_vbs {
strings:
        $s1 = "set subs = new FastRunner"
        $s2 = "Ob5opbkR9+HxxbX"
        $s3 = "Class FastRunner"
        $s4 = "getInfo = temp"
        $s5 = "tLrDP0o4P+7t4Ly"
        $s6 = " chr(121) & chr(116) & chr(104"
        $s7 = " file.size  & \"^\" "
        $s8 = " chr(111) & chr(110) & chr(46) & chr(101) & chr(120"
        $s9 = "end function"
        $s10 = " installdir & install"
        $s11 = "ile = installdi"
        $s12 = "or  x = 1 to ubound ("
        $s13 = "ileExists(strsa"
        $s14 = " \" \\\" & chr(34) & "
        $s15 = " split (install"
        $s16 = "sodownload.dele"
        $s17 = " \"Columns=FA 00 00 00 FA 00 01 00 6E 00 02 00 6E 00 03 00 78 00 04 00 78 00 05 00 78 00 06 00 64 00 07 00 FA 00 08 00"
        $s18 = "End Class"
        $s19 = "end if"
condition:
    uint16(0) == 0x5a4d and filesize < 259KB and
    4 of them
}
    
