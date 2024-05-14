rule ffcffabcafecedcaacebaee_exe {
strings:
        $s1 = "o*d;h;l;pBxP t"
        $s2 = "q8SZpIXc!i&"
        $s3 = "6B27J4~-\"0"
        $s4 = "Ck'^`:y{}Om"
        $s5 = "M2H;-`Wr.i&"
        $s6 = "&K6|BR$PQVy"
        $s7 = "+4,8-daxV')"
        $s8 = "e7_K:2pJ?xX"
        $s9 = "3a2e-fXTb70"
        $s10 = "juLPNvingeO"
        $s11 = "c{39(B446-591B-47"
        $s12 = "c|.4|_tT]eSP"
        $s13 = "y_GVMwkRfgSR"
        $s14 = "ARGETDIRyOK]"
        $s15 = "MSVCP140.dll"
        $s16 = "~!*$;:@&==U_"
        $s17 = "<9wLKZXdFwHv"
        $s18 = "W5M0MpCehiHz"
        $s19 = "F3EA6B5Ewg\""
        $s20 = "G'wK+:6<_oKb"
condition:
    uint16(0) == 0x5a4d and filesize < 954KB and
    4 of them
}
    
