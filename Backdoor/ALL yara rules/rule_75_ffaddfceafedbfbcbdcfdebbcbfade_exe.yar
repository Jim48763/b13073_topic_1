rule ffaddfceafedbfbcbdcfdebbcbfade_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "claMediumseagreen"
        $s4 = "ttdSecondaryPanel"
        $s5 = "TThemedDatePicker"
        $s6 = "FCaptionEmulation"
        $s7 = "ControlClassNameT"
        $s8 = "FAlignControlList"
        $s9 = "FCreatingMainForm"
        $s10 = "StaticSynchronize"
        $s11 = "EndFunctionInvoke"
        $s12 = "ToShortUTF8String"
        $s13 = "FRecreateChildren"
        $s14 = "MouseWheelHandler"
        $s15 = "CoAddRefServerProcess"
        $s16 = "ttbThumbBottomFocused"
        $s17 = "UnRegisterStyleEngine"
        $s18 = "Argument out of range"
        $s19 = "sfButtonTextPressed"
        $s20 = "tspMoreProgramsArrowHot"
condition:
    uint16(0) == 0x5a4d and filesize < 2187KB and
    4 of them
}
    
