rule ebbbfeabfcbefcbeecfecdfcfefef_exe {
strings:
        $s1 = "zMsM\\Fjx\\bq[@WZ"
        $s2 = "5OQX<^`PkkxOQs^w`"
        $s3 = "pHXRpSKHWSw\\ycrR"
        $s4 = "QPQG/U6\\o4\\pO[D"
        $s5 = "VOu\\RLM~Y\\NWNSv"
        $s6 = "i]`SKQfNQr:QhX"
        $s7 = "eh7iesMlqkTQne"
        $s8 = "jj]Hj7gXlNSZqM"
        $s9 = "KgnGnS{hn?^VR]"
        $s10 = "mdldiedTXPpJ<7"
        $s11 = "b>C?S<V|{~^Tbb"
        $s12 = "}Pn_wbyYJ]YhY="
        $s13 = "cznxbchsagdjashkdhkaj"
        $s14 = "TkoUTGFZGk{TqcUo~e"
        $s15 = "jgGpr[sk~{`"
        $s16 = "xL2|}OZ6Ut_"
        $s17 = "ArFTefmZJMI"
        $s18 = "NTdO:cm7Wlr"
        $s19 = "TPLuCJnOQ[]"
        $s20 = "@x~zIJyFLGf"
condition:
    uint16(0) == 0x5a4d and filesize < 137KB and
    4 of them
}
    
