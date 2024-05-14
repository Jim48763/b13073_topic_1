rule Trojan_RegFuck_exe {
strings:
        $s1 = ")\\=D81aC4h\"B"
        $s2 = "2z@j\"@SVE@[1="
        $s3 = "`!2Fk_?\"EnW\\"
        $s4 = "STAThreadAttribute"
        $s5 = "`4JrH]/B@m$"
        $s6 = "7b?E*+pGKRV"
        $s7 = "9\"NqUS',Oh"
        $s8 = "9s%4UyEe3qY"
        $s9 = "\"_=aD,q5]x"
        $s10 = "L`'v\"5Dq4_"
        $s11 = "0/1!vdgf~VY"
        $s12 = "/X{r%Wai\"V"
        $s13 = "6Xa@Tfhc{$A"
        $s14 = "bog(_z1A^Q-"
        $s15 = "jx\"VUGdB#q"
        $s16 = "NXADz!%ZTi7"
        $s17 = "ProductName"
        $s18 = "1Dt_jF\"vW7"
        $s19 = ":BSn)*rk[,G"
        $s20 = "OK#[qfkVI5b"
condition:
    uint16(0) == 0x5a4d and filesize < 12385KB and
    4 of them
}
    
