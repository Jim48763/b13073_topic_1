rule eabfafbdedcfafefacfacffdaf_dll {
strings:
        $s1 = " disponible en este momento, intente nuevamente m"
        $s2 = "BufferedPaintInit"
        $s3 = "0IdHTTPHeaderInfo"
        $s4 = "FCreatingMainForm"
        $s5 = "FRecreateChildren"
        $s6 = "OMIT_SHARED_CACHE"
        $s7 = "clInactiveCaption"
        $s8 = "FCaptionEmulation"
        $s9 = "OnSocketAllocated"
        $s10 = "OMIT_TCL_VARIABLE"
        $s11 = "StaticSynchronize"
        $s12 = "FLeftFromLastTime"
        $s13 = "Common Start Menu"
        $s14 = "TerminateAllYarns"
        $s15 = "claMediumseagreen"
        $s16 = "ToShortUTF8String"
        $s17 = "Tabular Text File"
        $s18 = "twMDISysButtonHot"
        $s19 = "TThemedDatePicker"
        $s20 = "MouseWheelHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 6815KB and
    4 of them
}
    
