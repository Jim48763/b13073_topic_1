rule eeadbbeddbfbdcdeedcecd_exe {
strings:
        $s1 = "@mL`\"ip2nl"
        $s2 = "%/4MS`&5;=C"
        $s3 = "9H P!X\"S@#"
        $s4 = ">xpGObj| La"
        $s5 = "( sH8 guard/"
        $s6 = "YLibTomMathom"
        $s7 = "ApisANSI\\a6["
        $s8 = "mp2.840.113549"
        $s9 = "    </security>"
        $s10 = "VirtualProtect"
        $s11 = "2LxX<3+eGd"
        $s12 = "n&NSTRUC,D"
        $s13 = "<KHLTN`O#G"
        $s14 = "D49aOf\"yP"
        $s15 = "e-P;>0faul"
        $s16 = "9r@VHWPZXe"
        $s17 = "-cei)flox/l"
        $s18 = "+624?CDr 4P"
        $s19 = "Object(Crea"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 161KB and
    4 of them
}
    
