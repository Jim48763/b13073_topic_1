import pe
rule ebcddaedebabbdeeeecfadc_exe {
strings:
        $s1 = "pszImplementation"
        $s2 = "ManagementBaseObject"
        $s3 = "Failed to load 404."
        $s4 = "RuntimeHelpers"
        $s5 = "MarshalAsAttribute"
        $s6 = "RuntimeFieldHandle"
        $s7 = "VarFileInfo"
        $s8 = "_CorExeMain"
        $s9 = "PixelFormat"
        $s10 = "FileDescription"
        $s11 = "Drive {0}\\ - {1}"
        $s12 = "GetDirectoryName"
        $s13 = "GetConsoleWindow"
        $s14 = "RblxCookieLogger"
        $s15 = "System.Net.Http.Headers"
        $s16 = "get_CurrentDirectory"
        $s17 = "DataProtectionScope"
        $s18 = "$$method0x6000041-1"
        $s19 = "RegexOptions"
        $s20 = "Dictionary`2"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
rule cccedcbefaabccfbedfdcdaabadfc_exe {
strings:
        $s1 = "pszImplementation"
        $s2 = "ManagementBaseObject"
        $s3 = "RuntimeHelpers"
        $s4 = "MarshalAsAttribute"
        $s5 = "RuntimeFieldHandle"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "PixelFormat"
        $s9 = "FileDescription"
        $s10 = "Drive {0}\\ - {1}"
        $s11 = "GetDirectoryName"
        $s12 = "GetConsoleWindow"
        $s13 = "System.Net.Http.Headers"
        $s14 = "get_CurrentDirectory"
        $s15 = "DataProtectionScope"
        $s16 = "$$method0x6000041-1"
        $s17 = "RegexOptions"
        $s18 = "Dictionary`2"
        $s19 = "/flat/48.png"
        $s20 = "DialogResult"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
rule ceefaaeeccdfefabddfe_exe {
strings:
        $s1 = "pszImplementation"
        $s2 = "ManagementBaseObject"
        $s3 = "RuntimeHelpers"
        $s4 = "MarshalAsAttribute"
        $s5 = "RuntimeFieldHandle"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "PixelFormat"
        $s9 = "FileDescription"
        $s10 = "Drive {0}\\ - {1}"
        $s11 = "GetDirectoryName"
        $s12 = "GetConsoleWindow"
        $s13 = "System.Net.Http.Headers"
        $s14 = "get_CurrentDirectory"
        $s15 = "DataProtectionScope"
        $s16 = "$$method0x6000041-1"
        $s17 = "RegexOptions"
        $s18 = "Dictionary`2"
        $s19 = "/flat/48.png"
        $s20 = "DialogResult"
condition:
    uint16(0) == 0x5a4d and filesize < 195KB and
    4 of them
}
    
rule abbfaefaacffaabcfdaafa_exe {
strings:
        $s1 = "pszImplementation"
        $s2 = "ManagementBaseObject"
        $s3 = "RuntimeHelpers"
        $s4 = "MarshalAsAttribute"
        $s5 = "RuntimeFieldHandle"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "PixelFormat"
        $s9 = "FileDescription"
        $s10 = "Drive {0}\\ - {1}"
        $s11 = "GetDirectoryName"
        $s12 = "GetConsoleWindow"
        $s13 = "System.Net.Http.Headers"
        $s14 = "get_CurrentDirectory"
        $s15 = "DataProtectionScope"
        $s16 = "$$method0x6000041-1"
        $s17 = "RegexOptions"
        $s18 = "Dictionary`2"
        $s19 = "/flat/48.png"
        $s20 = "DialogResult"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
rule aeeaddfdccbeedfedfd_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = ":$:,:4:<:D:L:T:\\:d:l:t:|: ;$;4;8;@;X;h;l;|;"
        $s3 = "$RENAMEDLG:IDCANCEL"
        $s4 = "q24\"hBK9.O"
        $s5 = "W=|Xtgk9sjc"
        $s6 = ",ns^gaci/+U"
        $s7 = "I9w\"@!M8'y"
        $s8 = "[HpUD3#W`Xg"
        $s9 = "d$N8m;{`W2a"
        $s10 = ".Kd2og'|eb>"
        $s11 = "FjT ^}P-Icf"
        $s12 = "9itgy)*v2ua"
        $s13 = "H$j\"e,+E=&"
        $s14 = "Nz-^l_?v9w7"
        $s15 = "#rAzpNBi\"h"
        $s16 = "R\"X;YW+dcs"
        $s17 = "w+(a{Y|lq[$"
        $s18 = "]fhvFTD24PV"
        $s19 = "IRN?Lgo1EFi"
        $s20 = "tF\"'ZE2vXU"
condition:
    uint16(0) == 0x5a4d and filesize < 8199KB and
    4 of them
}
    
rule bcaacaedabadfefdfeaacafcea_exe {
strings:
        $s1 = "pszImplementation"
        $s2 = "ManagementBaseObject"
        $s3 = "RuntimeHelpers"
        $s4 = "MarshalAsAttribute"
        $s5 = "RuntimeFieldHandle"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "PixelFormat"
        $s9 = "FileDescription"
        $s10 = "Drive {0}\\ - {1}"
        $s11 = "GetDirectoryName"
        $s12 = "GetConsoleWindow"
        $s13 = "System.Net.Http.Headers"
        $s14 = "get_CurrentDirectory"
        $s15 = "DataProtectionScope"
        $s16 = "$$method0x6000041-1"
        $s17 = "RegexOptions"
        $s18 = "Dictionary`2"
        $s19 = "/flat/48.png"
        $s20 = "DialogResult"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    