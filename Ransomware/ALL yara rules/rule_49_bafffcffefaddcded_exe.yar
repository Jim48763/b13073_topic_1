rule bafffcffefaddcded_exe {
strings:
        $s1 = "YD7\"(|6vwU"
        $s2 = "e=yjsL7{8^i"
        $s3 = "EKw'}V|aN#?"
        $s4 = "9`-?u6%mylH"
        $s5 = "nb.W)PlIB$/"
        $s6 = ";~:LVU`+ /X"
        $s7 = "tyM|1?LXBH2"
        $s8 = "o;N0Kwpu2:x"
        $s9 = "pB5c<F>~V3{"
        $s10 = "d%b2,zK>vW'"
        $s11 = "OK1\"9cBVrM"
        $s12 = "HwQCLM?U+'P"
        $s13 = "zd.`sZ6/W$o"
        $s14 = "7?JIQ5S+e_C"
        $s15 = "\"CP1{]<3ZR"
        $s16 = "RecP3Xaqlp7"
        $s17 = "]8tiDa'5P\""
        $s18 = "&Pd}#z5oFxa"
        $s19 = "B>t31n|rG{'"
        $s20 = "\"}1K/G(>9="
condition:
    uint16(0) == 0x5a4d and filesize < 6616KB and
    4 of them
}
    
