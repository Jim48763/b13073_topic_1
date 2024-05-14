rule cbbbdbedffecefaaaa_exe {
strings:
        $s1 = "    </security>"
        $s2 = "</assembly>"
        $s3 = "_XcptFilter"
        $s4 = "__getmainargs"
        $s5 = "_controlfp"
        $s6 = "msvcrt.dll"
        $s7 = "OpenProcess"
        $s8 = "kernel32.dll"
        $s9 = "__set_app_type"
        $s10 = "_environ"
        $s11 = "strlen"
        $s12 = "@.rsrc"
        $s13 = "@.data"
        $s14 = "__argv"
        $s15 = "memcpy"
        $s16 = "malloc"
        $s17 = "memset"
        $s18 = "Sleep"
        $s19 = ".text"
condition:
    uint16(0) == 0x5a4d and filesize < 5507KB and
    4 of them
}
    
