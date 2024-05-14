rule adcaaaebdbbfafbcfdbc_exe {
strings:
        $s1 = "WmfPlaceableFileHeader"
        $s2 = "GdipCreateMatrix3"
        $s3 = "BufferedPaintInit"
        $s4 = "Operation aborted"
        $s5 = "FCreatingMainForm"
        $s6 = "clInactiveCaption"
        $s7 = "FRightClickSelect"
        $s8 = "FCaptionEmulation"
        $s9 = "StaticSynchronize"
        $s10 = "TRttiClassRefType"
        $s11 = "TRttiManagedField"
        $s12 = "GdipGraphicsClear"
        $s13 = "Change group name"
        $s14 = "TMouseLeaveEventh"
        $s15 = "claMediumseagreen"
        $s16 = "ToShortUTF8String"
        $s17 = "ImageTypeMetafile"
        $s18 = "TMeasureItemEvent"
        $s19 = "Possible deadlock"
        $s20 = "twMDISysButtonHot"
condition:
    uint16(0) == 0x5a4d and filesize < 4725KB and
    4 of them
}
    
