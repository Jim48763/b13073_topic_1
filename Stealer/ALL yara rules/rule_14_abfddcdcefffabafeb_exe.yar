rule abfddcdcefffabafeb_exe {
strings:
        $s1 = "N%})/Mr TKt"
        $s2 = "D[-g&bt=nv "
        $s3 = "C\"NvrVgMw{"
        $s4 = ",.;(Lk_V}PA"
        $s5 = "l,4=zK5NQ{F"
        $s6 = "u^4{P/-FH!U"
        $s7 = "_\"K2Z(Ac#-"
        $s8 = "PYw}\"SCj0r"
        $s9 = "eZn Tt=8R_."
        $s10 = "|RZ4z-~!*pv"
        $s11 = "vC&\"3dX-U4"
        $s12 = "QwXe1+7{haE"
        $s13 = "^T-w:eCF`IG"
        $s14 = "5e)sZ7?b:M6"
        $s15 = "q~tFC)YI_14"
        $s16 = "f9W4+K@\"eb"
        $s17 = "^XuDEU&g|j_"
        $s18 = "&h;IJ|z:Dn'"
        $s19 = "Mgrm;Zy?_Gc"
        $s20 = "GetModuleHandleA"
condition:
    uint16(0) == 0x5a4d and filesize < 5859KB and
    4 of them
}
    
