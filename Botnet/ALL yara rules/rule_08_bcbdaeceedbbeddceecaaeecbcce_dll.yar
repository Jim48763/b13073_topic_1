rule bcbdaeceedbbeddceecaaeecbcce_dll {
strings:
        $s1 = "StaticSynchronize"
        $s2 = "EndFunctionInvoke"
        $s3 = "ToShortUTF8String"
        $s4 = "CoAddRefServerProcess"
        $s5 = "Argument out of range"
        $s6 = "EVariantBadVarTypeError"
        $s7 = "GetImplementedInterfaces"
        $s8 = "TAsyncConstArrayProc"
        $s9 = "Winapi.ActiveX"
        $s10 = "CurrencyFormat"
        $s11 = "IDOMNodeSelect"
        $s12 = "System.AnsiStrings"
        $s13 = "CoCreateInstanceEx"
        $s14 = "TLightweightEvent&"
        $s15 = "mkOperatorOverload"
        $s16 = "mkClassConstructor"
        $s17 = "TotalElementCounth"
        $s18 = "QualifiedClassName"
        $s19 = "LastIndexOf"
        $s20 = "GroupedWith"
condition:
    uint16(0) == 0x5a4d and filesize < 1111KB and
    4 of them
}
    
