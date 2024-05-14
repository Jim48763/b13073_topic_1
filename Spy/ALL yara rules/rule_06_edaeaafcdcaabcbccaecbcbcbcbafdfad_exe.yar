rule edaeaafcdcaabcbccaecbcbcbcbafdfad_exe {
strings:
        $s1 = "BufferedPaintInit"
        $s2 = "FCreatingMainForm"
        $s3 = "FRecreateChildren"
        $s4 = "clInactiveCaption"
        $s5 = "FCaptionEmulation"
        $s6 = "OnSocketAllocated"
        $s7 = "StaticSynchronize"
        $s8 = "TRttiClassRefType"
        $s9 = "TerminateAllYarns"
        $s10 = "EJclRegistryError"
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
    uint16(0) == 0x5a4d and filesize < 11282KB and
    4 of them
}
    
