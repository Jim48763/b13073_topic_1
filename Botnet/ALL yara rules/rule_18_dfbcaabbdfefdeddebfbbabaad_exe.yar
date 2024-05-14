rule dfbcaabbdfefdeddebfbbabaad_exe {
strings:
        $s1 = "%W2%nor%WrpqrWr%Wstu%Wr%vwr%WrxyzWr%W{|}%Wr%~"
        $s2 = "mdzcFizTz#jOGM"
        $s3 = "]aubP.e6pP0B5P"
        $s4 = "OufMrp2GgzR"
        $s5 = "46X9T Kwe>d"
        $s6 = "DQ1OGWv6BdV"
        $s7 = "5~2F`pH X#4"
        $s8 = "?m5lCtYxVTM"
        $s9 = "c{2zjnQdUKV"
        $s10 = "G`*_9^Vyjmb"
        $s11 = "S|MqHztleV5"
        $s12 = "=[!B`&d0EWc"
        $s13 = "H{*wE,`%mJ<"
        $s14 = "ProductName"
        $s15 = "F_cCmzk5E8#"
        $s16 = "EFwHM9$viYx"
        $s17 = "3B\"D>}G&.<"
        $s18 = "w}|EBQ8Yh[ "
        $s19 = "2l_xj(1wbC;"
        $s20 = "nUdCuXTahVz"
condition:
    uint16(0) == 0x5a4d and filesize < 1331KB and
    4 of them
}
    
