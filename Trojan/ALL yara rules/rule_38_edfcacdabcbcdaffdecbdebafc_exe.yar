rule edfcacdabcbcdaffdecbdebafc_exe {
strings:
        $s1 = "CoInitializeEx"
        $s2 = "Y/~x-e@=# ,"
        $s3 = "&:S`p#g- 69"
        $s4 = "s_Z wXfeIGR"
        $s5 = "I4q-lUbV/nD"
        $s6 = ":'(T*%VfD- "
        $s7 = "zkjbf$R0.n5"
        $s8 = "Hy]ve<\".LG"
        $s9 = ",r_st-|!Yc$"
        $s10 = "~$c1T9eZ2Y`"
        $s11 = "6D8-w<^~cSy"
        $s12 = "kU5?d0^6r$/"
        $s13 = "$ @+:R=0I1X"
        $s14 = "!~?2ZT,hdMN"
        $s15 = "M*{qkc>Y&hT"
        $s16 = "GetModuleHandleA"
        $s17 = "'AZ\\#qV*8U^"
        $s18 = "//B<i w06M!["
        $s19 = "2^U2vN,'McwB"
        $s20 = "OLEAUT32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 3442KB and
    4 of them
}
    
