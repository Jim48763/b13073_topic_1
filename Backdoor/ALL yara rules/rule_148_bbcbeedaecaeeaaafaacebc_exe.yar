rule bbcbeedaecaeeaaafaacebc_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "Directory not empty"
        $s3 = "Runtime Error!"
        $s4 = "No child processes"
        $s5 = "GetConsoleOutputCP"
        $s6 = "?Q6dIw5YUPp"
        $s7 = "1Q]cG.o3Wz "
        $s8 = "vC'DTE^X5K:"
        $s9 = "LufGeYq<)2["
        $s10 = "<kR>IYV?zd}"
        $s11 = "ljy'C3;P9p]"
        $s12 = "5du_HN9hIzB"
        $s13 = "IR9wQ;\"^g}"
        $s14 = "(z4B5Haq~,_"
        $s15 = "i<nZu/b=Wwp"
        $s16 = "F=+t>_bu][-"
        $s17 = "T8kD`Ju;dvb"
        $s18 = "Wroen\"jQp."
        $s19 = "3+.lIk~%@q^"
        $s20 = "#4WOCoBn\"H"
condition:
    uint16(0) == 0x5a4d and filesize < 7448KB and
    4 of them
}
    
