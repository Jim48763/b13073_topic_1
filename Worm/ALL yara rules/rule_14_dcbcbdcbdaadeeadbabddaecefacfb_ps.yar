rule dcbcbdcbdaadeeadbabddaecefacfb_ps {
strings:
        $s1 = "start-sleep -s 3"
        $s2 = "End Function"
        $s3 = "</script>"
        $s4 = "self.close"
        $s5 = "var_func"
        $s6 = "    }"
condition:
    uint16(0) == 0x5a4d and filesize < 60KB and
    4 of them
}
    
