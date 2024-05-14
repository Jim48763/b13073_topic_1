rule cbacaebdccdbbeefbcfcbbabee_exe {
strings:
        $s1 = "asn1:\"optional\""
        $s2 = "*syscall.Sockaddr"
        $s3 = "*[]map[string]int"
        $s4 = "runtime.runqsteal"
        $s5 = "unicode.Cuneiform"
        $s6 = "$f64.3fc7466496cb03de"
        $s7 = "$f64.bf61bf380a96073f"
        $s8 = "$f64.c03670e242712d62"
        $s9 = "$f64.3fd2fad9315255cf"
        $s10 = "$f64.bf843412600d6435"
        $s11 = "$f64.404601e678fc457b"
        $s12 = "runtime.cansemacquire"
        $s13 = "$f64.bfd4cd7d691cb913"
        $s14 = "$f64.c031c209555f995a"
        $s15 = "$f64.3f5a01a019fe5585"
        $s16 = "$f64.3f960290af9f12bc"
        $s17 = "$f64.3fe14af092eb6f33"
        $s18 = "$f64.3fb0a54c5536ceba"
        $s19 = "$f64.3e91642d7ff202fd"
        $s20 = "$f64.c0a69c6c36da2dfb"
condition:
    uint16(0) == 0x5a4d and filesize < 3110KB and
    4 of them
}
    
