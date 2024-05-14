rule bffadfababaadadcbefacddf_exe {
strings:
        $s1 = "56<?BEUX`ep"
        $s2 = "FdHi&InLOp>"
        $s3 = "K8dH*+4L@I,"
        $s4 = ",K:_CEP8H?D"
        $s5 = "8singu3 :le"
        $s6 = "Bag_mubyh\""
        $s7 = "_\"hjgoafdpddmf"
        $s8 = "O@hpnlpagcnaknjd"
        $s9 = "(r$C( =h`N6!"
        $s10 = "SOFTWARE\\M&"
        $s11 = "7Q<L&Cl(1$B1"
        $s12 = "x@6;>|pfDo@`"
        $s13 = "SkSmSoYiZlZpZs\""
        $s14 = "U~VllErrx;GCD"
        $s15 = "0<N<MMp\"L$BV"
        $s16 = "RM9 A\"* MD;%"
        $s17 = "\\JXE{RX264UZ"
        $s18 = "VirtualProtect"
        $s19 = "L($pT@9q&/"
        $s20 = "_XLbU A%p#"
condition:
    uint16(0) == 0x5a4d and filesize < 733KB and
    4 of them
}
    
