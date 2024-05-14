rule bebebfefabedbceadbdffc_exe {
strings:
        $s1 = "g;)]\"}-oH8"
        $s2 = "-A06sD|7H9<"
        $s3 = "`5bF4E|]{p-"
        $s4 = "k6'Cbc$x !]"
        $s5 = "zY$P{vxO5kW"
        $s6 = "Ep/'}K2UQ%o"
        $s7 = "wqhBC:t(<Pu"
        $s8 = "GetModuleHandleA"
        $s9 = "zpP*pijUtn\""
        $s10 = "#:N!ZEcIt**|"
        $s11 = "HttpSendRequestW"
        $s12 = "s8*~C0r*\\e4)"
        $s13 = "CryptUnprotectData"
        $s14 = "9I\"-PE7`h"
        $s15 = "&VhA3$-4+6"
        $s16 = "xLdhsQ\"^*"
        $s17 = "`[GS#-nf;g"
        $s18 = "sIhfDdHz.#"
        $s19 = "p}qP#wvl+Y"
        $s20 = "T]#J{1: |/"
condition:
    uint16(0) == 0x5a4d and filesize < 1448KB and
    4 of them
}
    
