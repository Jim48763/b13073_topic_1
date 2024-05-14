rule fcccbbbedbcbcbeeebcfa_exe {
strings:
        $s1 = "F6 NDSPak:l"
        $s2 = "O|1CdbP3Z>t"
        $s3 = "ZESPMBW_r7K"
        $s4 = "1CSV86A2cqx"
        $s5 = "RMzLmyFGs6;"
        $s6 = "paR~n2\"|Ok"
        $s7 = "9UNemHOEfGx"
        $s8 = "GetConsoleWindow"
        $s9 = "R6d36UekOEKl"
        $s10 = "ElIAVv9gqA9w2"
        $s11 = "acmStreamClose"
        $s12 = "ImmDestroyIMCC"
        $s13 = "GetDeviceCaps"
        $s14 = "VirtualProtect"
        $s15 = "rXLo8q537D"
        $s16 = ":rB]E`)4QW"
        $s17 = "P{/@(#S}AW"
        $s18 = "\"Of>ym=El"
        $s19 = "2)zn%4~Y3="
        $s20 = "kB\"'7645E"
condition:
    uint16(0) == 0x5a4d and filesize < 503KB and
    4 of them
}
    
