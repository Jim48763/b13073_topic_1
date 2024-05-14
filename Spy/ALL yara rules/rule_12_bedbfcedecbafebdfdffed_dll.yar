rule bedbfcedecbafebdfdffed_dll {
strings:
        $s1 = "System.JSON.Types"
        $s2 = "BufferedPaintInit"
        $s3 = "AsTimeStampOffset"
        $s4 = "IsConcurrencyType"
        $s5 = "FSupportedStreams"
        $s6 = "TACBrBALMagellanL"
        $s7 = "0IdHTTPHeaderInfo"
        $s8 = "Parameter count: "
        $s9 = "TACBrBALLucasTec6"
        $s10 = "FCreatingMainForm"
        $s11 = "ACBrNFeDANFEClass"
        $s12 = "SearchExactString"
        $s13 = "LineWidthCBChange"
        $s14 = "clInactiveCaption"
        $s15 = "FResetPageNumbers"
        $s16 = "ClosedByteReader@"
        $s17 = "FRightClickSelect"
        $s18 = "getSQLDriverMYSQL"
        $s19 = "EnderecoPrincipal"
        $s20 = "FCaptionEmulation"
condition:
    uint16(0) == 0x5a4d and filesize < 11164KB and
    4 of them
}
    
