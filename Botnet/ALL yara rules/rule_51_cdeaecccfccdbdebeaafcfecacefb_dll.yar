rule cdeaecccfccdbdebeaafcfecacefb_dll {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "EVariantDispatchError"
        $s3 = "EVariantBadVarTypeError"
        $s4 = "ImmSetCompositionFontA"
        $s5 = " 2001, 2002 Mike Lischke"
        $s6 = "TBitmapCanvasd"
        $s7 = "GetWindowTheme"
        $s8 = "TWinControlActionLink"
        $s9 = "; ;$;(;,;0;4;8;<;@;D;H;L;P;T;X;\\;`;P>q>^?"
        $s10 = "CoCreateInstanceEx"
        $s11 = "TMSDOMNamedNodeMap"
        $s12 = "EExternalException"
        $s13 = "TContextPopupEvent"
        $s14 = "GetWindowDC"
        $s15 = "TBrushStyle"
        $s16 = "fsStayOnTop"
        $s17 = "Medium Gray"
        $s18 = "LoadStringA"
        $s19 = "VarFileInfo"
        $s20 = "IntervalXEA"
condition:
    uint16(0) == 0x5a4d and filesize < 557KB and
    4 of them
}
    
