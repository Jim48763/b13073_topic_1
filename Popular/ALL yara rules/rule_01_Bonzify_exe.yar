rule Bonzify_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "~zwxuy|xvypr{xy{}tx~|"
        $s3 = "{y{~|{sv{ywuwvxtqrz~y"
        $s4 = " instituer tout litige qui pourrait d"
        $s5 = "What did the beaver say to the tree?"
        $s6 = "~}vy|wqqwumtz{wtyyz|wyxz"
        $s7 = "065CB?11:;1.(&"
        $s8 = "yutvutpprqquywvsxyz|z"
        $s9 = "F]#$eyo'GRg"
        $s10 = "[F@y:f2DQab"
        $s11 = "h:R2CY!=V(+"
        $s12 = "MEU-_B5w]=T"
        $s13 = "5[aN2*:MJ8%"
        $s14 = "TXr1@Y)]qaI"
        $s15 = "ProductName"
        $s16 = "$6rx]h8\"sC"
        $s17 = "}Zu8&@yJF{I"
        $s18 = "Idle1_9 (3)"
        $s19 = "%=Tfqsl^J5 "
        $s20 = "oQ:-1DMu*cP"
condition:
    uint16(0) == 0x5a4d and filesize < 6549KB and
    4 of them
}
    
