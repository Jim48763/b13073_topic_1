rule daddedfbcfaabbefceddeeccfadc_exe {
strings:
        $s1 = "Transferred from (A/C no. )        : "
        $s2 = "+jom94Tw~/1"
        $s3 = "del LOG.DAT"
        $s4 = "rJp<aY-|0e>"
        $s5 = "GetModuleHandleA"
        $s6 = "A/C type <S/F>  : "
        $s7 = "Enter first name : "
        $s8 = "Total Balance   : %s"
        $s9 = "SetConsoleCursorPosition"
        $s10 = "CertGetCRLContextProperty"
        $s11 = "Transfered+to+"
        $s12 = "Received+from+"
        $s13 = "BANK MANAGEMENT SYSTEM"
        $s14 = ">~xLdD4%Q8"
        $s15 = "#\"_V1Lk9<"
        $s16 = "%X'+_.#)\""
        $s17 = "TMEkCXy(NF"
        $s18 = "A9ynwDK6aM"
        $s19 = "Do LK{5O2m"
        $s20 = "Page : %d out of %d"
condition:
    uint16(0) == 0x5a4d and filesize < 495KB and
    4 of them
}
    
