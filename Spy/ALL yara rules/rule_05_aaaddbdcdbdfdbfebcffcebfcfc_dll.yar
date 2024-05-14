rule aaaddbdcdbdfdbfebcffcebfcfc_dll {
strings:
        $s1 = "BufferedPaintInit"
        $s2 = "FCreatingMainForm"
        $s3 = "FRecreateChildren"
        $s4 = "ImageAlignmentX9A"
        $s5 = "clInactiveCaption"
        $s6 = "FCaptionEmulation"
        $s7 = "OnSocketAllocated"
        $s8 = "ControlClassNameT"
        $s9 = "StaticSynchronize"
        $s10 = "TerminateAllYarns"
        $s11 = "claMediumseagreen"
        $s12 = "UnregisterWeakRef"
        $s13 = "ToShortUTF8String"
        $s14 = "twMDISysButtonHot"
        $s15 = "msctls_progress32"
        $s16 = "ReservedStackSize"
        $s17 = "TThemedDatePicker"
        $s18 = "MouseWheelHandler"
        $s19 = "EndFunctionInvoke"
        $s20 = "CoAddRefServerProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 8518KB and
    4 of them
}
    
