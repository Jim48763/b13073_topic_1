rule Ransomware_Satana_exe {
strings:
        $s1 = "hcqzqdnqhvfbsrryd"
        $s2 = "GetLocalTime"
        $s3 = "Dtheyk[p{olp"
        $s4 = "mtkedgildxvj"
        $s5 = "Veu[qljtotrrP"
        $s6 = "bapbjfrknvrsmfmrn"
        $s7 = "on_tls_callback2"
        $s8 = "glPointSize"
        $s9 = "faasulcmnej"
        $s10 = "glLineWidth"
        $s11 = "tydqcgfwwka"
        $s12 = "KERNEL32.dll"
        $s13 = "UWRjyZZ_]PP|"
        $s14 = "yaqrbysjaqmdw"
        $s15 = "<*<5<@<O=X=R>j>o>"
        $s16 = "qwvywvszdcvle"
        $s17 = "USER32.dll"
        $s18 = "Bg~[`jkaM~"
        $s19 = "glVertex3d"
        $s20 = "MessageBoxA"
condition:
    uint16(0) == 0x5a4d and filesize < 54KB and
    4 of them
}
    
