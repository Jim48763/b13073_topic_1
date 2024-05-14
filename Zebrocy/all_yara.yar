import pe
rule cedccadffeeffaeddbefeabcdfcf_exe {
strings:
        $s1 = "*syscall.LazyProc"
        $s2 = "crypto/md5/md5.go"
        $s3 = "*tls.keyAgreement"
        $s4 = "net.SplitHostPort"
        $s5 = "*big.RoundingMode"
        $s6 = "*[]map[string]int"
        $s7 = "runtime.emptyfunc"
        $s8 = ")?/a*F,#)_+-){*7)"
        $s9 = "*map[uint32]int32"
        $s10 = "*rc4.KeySizeError"
        $s11 = "main.DeleteObject"
        $s12 = "syscall.Signal.String"
        $s13 = "FirstMulticastAddress"
        $s14 = "CRLDistributionPoints"
        $s15 = "assignEncodingAndSize"
        $s16 = "*runtime.stringStruct"
        $s17 = "*http.http2PriorityParam"
        $s18 = "hasScavengeCandidate"
        $s19 = "*cipher.cbcEncrypter"
        $s20 = "strings.ContainsRune"
condition:
    uint16(0) == 0x5a4d and filesize < 4805KB and
    4 of them
}
    
rule dcbdfebafbefbeaaefedcfa_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TInterfacedPersistent"
        $s3 = "CoAddRefServerProcess"
        $s4 = "TCustomControlAction"
        $s5 = "ImmSetCompositionFontA"
        $s6 = "GetEnhMetaFilePaletteEntries"
        $s7 = "clWebLightSteelBlue"
        $s8 = "Directory not empty"
        $s9 = " 2001, 2002 Mike Lischke"
        $s10 = ":p=w=~=P>`>P?U?d?i?x?}?"
        $s11 = "TIdStatusEvent"
        $s12 = "CoInitializeEx"
        $s13 = "SetWindowTheme"
        $s14 = "ckRunningOrNew"
        $s15 = "clWebPaleVioletRed"
        $s16 = "EIdUnknownProtocol"
        $s17 = "TContextPopupEvent"
        $s18 = "Windows-31J"
        $s19 = "WSAJoinLeaf"
        $s20 = "fsStayOnTop"
condition:
    uint16(0) == 0x5a4d and filesize < 698KB and
    4 of them
}
    