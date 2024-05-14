rule ebdffbeedbfabfecfcbbdbed_exe {
strings:
        $s1 = "StaticSynchronize"
        $s2 = "TRttiClassRefType"
        $s3 = "ToShortUTF8String"
        $s4 = "ReservedStackSize"
        $s5 = "EndFunctionInvoke"
        $s6 = "Argument out of range"
        $s7 = "EVariantDispatchError"
        $s8 = "GetImplementedInterfaces"
        $s9 = "SetDefaultDllDirectories"
        $s10 = "/SILENT, /VERYSILENT"
        $s11 = "TAsyncConstArrayProc"
        $s12 = "ECompressInternalError"
        $s13 = "OnFindAncestor"
        $s14 = "Winapi.ActiveX"
        $s15 = "DictionarySize"
        $s16 = "TRttiRecordMethod|"
        $s17 = "QualifiedClassName"
        $s18 = "mkOperatorOverload"
        $s19 = "|0\"Yu%aOGv"
        $s20 = "UnitNameFld"
condition:
    uint16(0) == 0x5a4d and filesize < 7133KB and
    4 of them
}
    
