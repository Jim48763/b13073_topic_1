rule VBS_LoveLetter_txt_vbs {
strings:
        $s1 = "dim lines,n,dta1,dta2,dt1,dt2,dt3,dt4,l1,dt5,dt6"
        $s2 = "elseif num = 3 then"
        $s3 = "sub listadriv"
        $s4 = " odpowiedz.\""
        $s5 = "fileexist = msg"
        $s6 = "for each f1 in sf"
        $s7 = "eq=folderspec"
        $s8 = "set fc = f.Files"
        $s9 = "scriptini.close"
        $s10 = "sub main()"
        $s11 = "listadriv()"
        $s12 = "downread=\"\""
        $s13 = "end function"
        $s14 = "ext=lcase(ext)"
        $s15 = "att.attributes=att.attributes+2"
        $s16 = "d.write dt6"
        $s17 = "dim wscr,rr"
        $s18 = "regad=\"\""
        $s19 = "Dim d,dc,s"
        $s20 = "dim f,f1,sf"
condition:
    uint16(0) == 0x5a4d and filesize < 14KB and
    4 of them
}
    
