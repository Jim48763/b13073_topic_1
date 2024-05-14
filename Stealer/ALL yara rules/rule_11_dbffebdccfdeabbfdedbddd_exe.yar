rule dbffebdccfdeabbfdedbddd_exe {
strings:
        $s1 = ".ClassLibrary1.dll"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "op_Equality"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "ResolveEventArgs"
        $s8 = "Synchronized"
        $s9 = "DigiCert1%0#"
        $s10 = "d..igHkqx!OQ"
        $s11 = "E%RP/:^E9XK~"
        $s12 = "GeneratedCodeAttribute"
        $s13 = "GetTotalMemory"
        $s14 = "Fzhygpyikjnfzf"
        $s15 = "CallSiteBinder"
        $s16 = "GzipDecompress"
        $s17 = "San Francisco1"
        $s18 = "defaultInstance"
        $s19 = "DebuggingModes"
        $s20 = "LegalTrademarks"
condition:
    uint16(0) == 0x5a4d and filesize < 223KB and
    4 of them
}
    
