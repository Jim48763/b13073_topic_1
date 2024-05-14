rule affebbcebfdbacbdcffafcaaf_vbs {
strings:
        $s1 = "Execute(temp) "
        $s2 = "if t <> 0 then"
        $s3 = "temp = \"\""
        $s4 = "t = t + 1"
        $s5 = "end if"
        $s6 = "i=i+1"
        $s7 = "i = 0"
condition:
    uint16(0) == 0x5a4d and filesize < 18KB and
    4 of them
}
    
