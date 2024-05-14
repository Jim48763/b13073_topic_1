rule caaacccffddfeffecadbfb_exe {
strings:
        $s1 = "!#W|3EF%\".!:!"
        $s2 = "Wku5cu-r S/Zu'"
        $s3 = "W~qualrrorxist"
        $s4 = "#4$|3l'\\m[f\""
        $s5 = "~ #4MwYfT<("
        $s6 = "jb~LMX>cNxd"
        $s7 = "Mq(^0KUAoTL"
        $s8 = "*%d:\"&#34;"
        $s9 = "A\"Ty^lb09t"
        $s10 = "f\"p_.^bIe*"
        $s11 = "IJT8$liUB^%"
        $s12 = "NSsql.DBTxw"
        $s13 = "k\"mgtsyvxd"
        $s14 = ".pkcs86Xaxh"
        $s15 = "}Zl'M&81)42"
        $s16 = "gubmfM9a\"X"
        $s17 = "0#GN6\"1m`|"
        $s18 = "L,hfTli]Zu)"
        $s19 = "i.z'Bs1]L}G"
        $s20 = "c/oualm23Cd"
condition:
    uint16(0) == 0x5a4d and filesize < 3162KB and
    4 of them
}
    
