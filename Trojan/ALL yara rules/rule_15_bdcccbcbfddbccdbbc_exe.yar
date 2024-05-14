rule bdcccbcbfddbccdbbc_exe {
strings:
        $s1 = "%l ^l^eMdJ Yx@sMs"
        $s2 = "fvlZ _u\\p\\rH @s"
        $s3 = "PopupWindowFinder"
        $s4 = "s?\\,e,t3c<\\)h9o"
        $s5 = "EventFiringWebElement"
        $s6 = "AssemblyBuilderAccess"
        $s7 = "wrappedOptions"
        $s8 = "1fAjtWeBtEcRtY"
        $s9 = ",cMn]oH MeMa|h"
        $s10 = "EQaNlIMVnII]eT"
        $s11 = ",{,U3n<k)n9ow?n,},"
        $s12 = "LogicalCallContext"
        $s13 = ")/9sk?e,e,p3a<s)s9"
        $s14 = "ae[EGuTKzy~"
        $s15 = "x[IG]zMNEAX"
        $s16 = "3$>_^cTdsn?"
        $s17 = "@3/<s)o9rt?"
        $s18 = "xTl?vZr_iCn"
        $s19 = "'[,c3a<p)]9"
        $s20 = "XeKFErIwRlP"
condition:
    uint16(0) == 0x5a4d and filesize < 615KB and
    4 of them
}
    
