rule afdbfdcfdabfcdeaefbafeddcaf_exe {
strings:
        $s1 = "w]Q(OqaGfsA"
        $s2 = "m6NfcO/$dRxm"
        $s3 = "MBYeO\"[-L"
        $s4 = "h%~= ]Lgx5"
        $s5 = "El)[e7&CAI"
        $s6 = "v<`SM:XU|B"
        $s7 = "U'KQ\"&I1~"
        $s8 = "}1`SM:XU\\:y"
        $s9 = "P.I9|fJ9~&"
        $s10 = "_9PM;[&M=}"
        $s11 = "5\\vAhNZ2e"
        $s12 = "{1m}C\"<-{"
        $s13 = "])%Hq9{uuI"
        $s14 = "0mG&hoElp"
        $s15 = "!`h/px?gc"
        $s16 = "1k<4@s9DV"
        $s17 = "*2Xk'>bg#"
        $s18 = "{m8Z5w\"="
        $s19 = ")+*\">~5W"
        $s20 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD"
condition:
    uint16(0) == 0x5a4d and filesize < 337KB and
    4 of them
}
    
