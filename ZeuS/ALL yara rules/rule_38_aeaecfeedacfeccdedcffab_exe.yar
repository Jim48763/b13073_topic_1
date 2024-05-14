rule aeaecfeedacfeccdedcffab_exe {
strings:
        $s1 = "7$ *\"'+,<:"
        $s2 = "t,WVj\"SUhX"
        $s3 = "Accept-Encoding"
        $s4 = "GetModuleHandleA"
        $s5 = "<_\\uKSWUjlh"
        $s6 = "bvfd^clmfej}"
        $s7 = "wine_get_unix_file_name"
        $s8 = "Proxy-Connection"
        $s9 = "SeSecurityPrivilege"
        $s10 = "InterlockedDecrement"
        $s11 = "If-Modified-Since"
        $s12 = "GetProcessHeap"
        $s13 = "7$ **/#$<l./-9/"
        $s14 = "D$,PVQWjzh"
        $s15 = "^NZ_M]dL[W"
        $s16 = "t Vj.^f91u"
        $s17 = "Connection: close"
        $s18 = "lvqkzjp6szy"
        $s19 = "p~fpt|h?{gy"
        $s20 = "waqHuvwpsxo"
condition:
    uint16(0) == 0x5a4d and filesize < 124KB and
    4 of them
}
    
