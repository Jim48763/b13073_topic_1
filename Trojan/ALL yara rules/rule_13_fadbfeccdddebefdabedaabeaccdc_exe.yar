rule fadbfeccdddebefdabedaabeaccdc_exe {
strings:
        $s1 = "CompareObjectGreater"
        $s2 = "A name was expected"
        $s3 = "set_TwitterClientVersion"
        $s4 = "Invalid left value"
        $s5 = "DebuggerVisualizer"
        $s6 = "ParseArgumentNames"
        $s7 = "ITwitterDataAccess"
        $s8 = "STAThreadAttribute"
        $s9 = "ExpectedTokenException"
        $s10 = "ZN|PArlB1KS"
        $s11 = "EbHZ CriB5@"
        $s12 = "ProductName"
        $s13 = "_CorExeMain"
        $s14 = "LastIndexOf"
        $s15 = "VarFileInfo"
        $s16 = "d!Ee+<n@rpC"
        $s17 = "ResolveToObject"
        $s18 = "FileDescription"
        $s19 = "IFormatProvider"
        $s20 = "ITweetRepository"
condition:
    uint16(0) == 0x5a4d and filesize < 755KB and
    4 of them
}
    
