rule beccafdaafabbeafdaebed_exe {
strings:
        $s1 = "t,WVj\"SUhX"
        $s2 = "Accept-Encoding"
        $s3 = "GetModuleHandleA"
        $s4 = "<_\\uKSWUjkh"
        $s5 = "6(45\" 0d.0,"
        $s6 = "yzdld`j}/imk"
        $s7 = "}ajwso{m>tjv"
        $s8 = "nC[ECGSPVWYO"
        $s9 = "wine_get_unix_file_name"
        $s10 = "Proxy-Connection"
        $s11 = "kNGWMPOGZjHJO"
        $s12 = "SeSecurityPrivilege"
        $s13 = "InterlockedDecrement"
        $s14 = "If-Modified-Since"
        $s15 = "iick}mTijklods"
        $s16 = "GetProcessHeap"
        $s17 = "|okaadhow'edfrd"
        $s18 = "D$,PVQWjuh"
        $s19 = "t Vj.^f91u"
        $s20 = "4,6@6@7D7H7L7P7T7X7\\7`7X<"
condition:
    uint16(0) == 0x5a4d and filesize < 122KB and
    4 of them
}
    
