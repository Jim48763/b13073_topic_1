rule dfcdcacedbfcbcdddfacaecf_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = ">$>,>4><>D>L>T>\\>d>l>t>|> ?$?4?8?@?X?h?l?|?"
        $s3 = "pH=NUt.K>}q"
        $s4 = "P\"?swM*96~"
        $s5 = "%.#(0),2D3C"
        $s6 = "q CR#^4wbre"
        $s7 = "\"YMsGw7^[l"
        $s8 = "aV:s\"W Y}J"
        $s9 = "QNe8@d`qi_;"
        $s10 = "{&Uqc=`iy(6"
        $s11 = "`A0^SnP3+X)"
        $s12 = "xLPr=J>U+9@"
        $s13 = "LZ3S-\"INq&"
        $s14 = "Xd/We+$rhR'"
        $s15 = "T2a+#5j@\"Y"
        $s16 = "}imchCFstxl"
        $s17 = "wMuKs8,nY<+"
        $s18 = "$P &N40F+)c"
        $s19 = "}De^&dT8l7U"
        $s20 = "c!tp2#Nw*H?"
condition:
    uint16(0) == 0x5a4d and filesize < 5269KB and
    4 of them
}
    