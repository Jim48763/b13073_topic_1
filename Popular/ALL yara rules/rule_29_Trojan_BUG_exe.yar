rule Trojan_BUG_exe {
strings:
        $s1 = "if dongu = 6 then"
        $s2 = "  For Each file in files"
        $s3 = "set_TransparencyKey"
        $s4 = "v2eprogrampathname"
        $s5 = "STAThreadAttribute"
        $s6 = "No ways to escape!"
        $s7 = "pictureBox3"
        $s8 = "5B-\"1(%{)h"
        $s9 = "ProductName"
        $s10 = "80K:T\"-9y$"
        $s11 = "ksXaDO2=\"."
        $s12 = "+W&[,@-u2#7"
        $s13 = "2!>+J:UObho"
        $s14 = "PB_WindowID"
        $s15 = "+k/G'f-.#4*"
        $s16 = "XUMPQ9=qB?/"
        $s17 = "7\"B-Q<aNsb"
        $s18 = "#c1w.k=|6!D"
        $s19 = "6(9:<OAcFvL"
        $s20 = "PKDmFW8 60*"
condition:
    uint16(0) == 0x5a4d and filesize < 3122KB and
    4 of them
}
    
