rule acecdfedbcfbeeeddafdacebcafa_dll {
strings:
        $s1 = "CanReuseTransform"
        $s2 = "ResolveTypeHandle"
        $s3 = "ManagementBaseObject"
        $s4 = "RuntimeHelpers"
        $s5 = "RuntimeFieldHandle"
        $s6 = "System.Linq"
        $s7 = "ProductName"
        $s8 = "IsComObject"
        $s9 = "#6k?u\"*ahH"
        $s10 = "IOException"
        $s11 = "#6k?+\"!@UE"
        $s12 = "#6k@D\"&Apt"
        $s13 = "#6k>E\"+(%K"
        $s14 = "#6k?i\"&T(!"
        $s15 = "#6k@i\"%<4j"
        $s16 = "#6k@`\"+^IQ"
        $s17 = "VarFileInfo"
        $s18 = "#6k?c\"+gOR"
        $s19 = "H\"$)%8xeV?"
        $s20 = "ThreadStaticAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 360KB and
    4 of them
}
    
