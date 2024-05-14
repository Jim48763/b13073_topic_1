rule eaedabfdcbcacdbdbdaffefffcaefa_exe {
strings:
        $s1 = "GdipGraphicsClear"
        $s2 = "GetKeyboardLayout"
        $s3 = "GetTouchInputInfo"
        $s4 = "HRnb[[ZObbbKjjjHrrrDzzz="
        $s5 = "            processorArchitecture=\"*\""
        $s6 = "5a6l6}6.8@8D8H8L8P8T8X8\\8`8d8h8l8p8t8"
        $s7 = "_beginthreadex"
        $s8 = "invalid string position"
        $s9 = "GdipMultiplyMatrix"
        $s10 = "GdipSetPenStartCap"
        $s11 = "GdipGetImageHeight"
        $s12 = "lutpb':nXF<"
        $s13 = "L[QG?><]7:V"
        $s14 = "PrintDlgExW"
        $s15 = "$Kds,PhD4Rf"
        $s16 = "Skew Bitmap"
        $s17 = "IaUyYENMviq"
        $s18 = "'MfL,Qh./Tj"
        $s19 = "VarFileInfo"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 6232KB and
    4 of them
}
    
