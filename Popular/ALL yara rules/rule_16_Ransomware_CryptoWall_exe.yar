rule Ransomware_CryptoWall_exe {
strings:
        $s1 = "5#505A5G5P5W5`5i5$6*666?6E6P6W6`6g6q6v6}6"
        $s2 = "Connection: close"
        $s3 = "C:\\out.png"
        $s4 = ")\"Oa\"Pc%?Q"
        $s5 = "eyea-a&u\""
        $s6 = "x9jSeq@gP"
        $s7 = "?-?-9-=7}["
        $s8 = "2E3L3\\3c3t3z3"
        $s9 = "F36[&?);)"
        $s10 = ":12r04Q&Q"
        $s11 = " AtUawwBW"
        $s12 = ":p\"TaT%g"
        $s13 = "6hehbz4fp"
        $s14 = "3;4K4d4q4{4"
        $s15 = "9\"~M\":!"
        $s16 = "! !<!de\""
        $s17 = "!'.\"\\k`"
        $s18 = "0 Rl1MQ&"
        $s19 = "oWaTl 3."
        $s20 = "Z)`bIBQG"
condition:
    uint16(0) == 0x5a4d and filesize < 137KB and
    4 of them
}
    
