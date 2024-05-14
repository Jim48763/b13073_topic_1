rule dcdbbecdecbfcebcadcc_exe {
strings:
        $s1 = "fmSS_Certificates"
        $s2 = "msctls_progress32"
        $s3 = "0IdHTTPHeaderInfo"
        $s4 = "lbVerCodeLifetime"
        $s5 = "SetDefaultDllDirectories"
        $s6 = "Colors.DropTargetBorderColor"
        $s7 = "PipeClient_MainPipeMessage"
        $s8 = "YIdHashMessageDigest"
        $s9 = "More information at:"
        $s10 = "AstRmtControlExport"
        $s11 = "lbCertificatesClick"
        $s12 = "seStartRowExit"
        $s13 = "RegSetValueExA"
        $s14 = "FormatCurrency"
        $s15 = "uAITableViewer"
        $s16 = "TVirtualStringTree"
        $s17 = "JclRegistry"
        $s18 = "sbCopy_hwid"
        $s19 = "nRegistryEx"
        $s20 = "\"kY!v&tb+$"
condition:
    uint16(0) == 0x5a4d and filesize < 5159KB and
    4 of them
}
    
