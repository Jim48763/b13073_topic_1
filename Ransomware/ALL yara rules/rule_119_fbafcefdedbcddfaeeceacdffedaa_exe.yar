rule fbafcefdedbcddfaeeceacdffedaa_exe {
strings:
        $s1 = "JAw:ip9hOdR"
        $s2 = "7;6DJHDVb>j~"
        $s3 = "~U7icX8yZT\\"
        $s4 = "R[_:EJQXXFMN"
        $s5 = "!((>B?1BL8GK}"
        $s6 = "%(\"LOLMWXXhj"
        $s7 = "HJFGKGLQO0Oaz"
        $s8 = "NQNEV^@EBMUWb"
        $s9 = "U^_N\\e9YrCT^"
        $s10 = "GetProcessHeap"
        $s11 = "gDw-<et(9Z"
        $s12 = "8=9@FE:Xo_"
        $s13 = "ZcfNer:LTx"
        $s14 = "6R)D|(dfu!"
        $s15 = "9ve:sfOuC~"
        $s16 = "NW4[pKO^y!"
        $s17 = "Ub:O}K4\")"
        $s18 = "SNg2^'jP?t"
        $s19 = "-79BD<JPoro"
        $s20 = "MdJYdI+ht<{h"
condition:
    uint16(0) == 0x5a4d and filesize < 493KB and
    4 of them
}
    
