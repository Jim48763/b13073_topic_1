rule cbbbecafdcfeeeacfcbdbdbdcedfa_com {
strings:
        $s1 = " Have a nice day,"
        $s2 = "$Goodbye."
        $s3 = "t\"< t"
condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    4 of them
}
    
