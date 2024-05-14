import pe
rule acbbbcebdbadfadfcebf_exe {
strings:
        $s1 = "l?JP5]*'Ce-"
        $s2 = "*V_W\"R4p,E"
        $s3 = "T=FGCr0SKL%"
        $s4 = "|9xM1&(+?RE"
        $s5 = "LoadStringW"
        $s6 = "ProgramFilesDir"
        $s7 = "IsWindowVisible"
        $s8 = "DialogBoxParamW"
        $s9 = "Not enough memory"
        $s10 = "GetModuleHandleW"
        $s11 = "DispatchMessageW"
        $s12 = "CRC failed in %s"
        $s13 = "CreateCompatibleBitmap"
        $s14 = "GetCurrentDirectoryW"
        $s15 = "SHBrowseForFolderW"
        $s16 = "OLEAUT32.dll"
        $s17 = "SetEndOfFile"
        $s18 = ">MIuHU\"x1Uh"
        $s19 = "</trustInfo>"
        $s20 = "GETPASSWORD1"
condition:
    uint16(0) == 0x5a4d and filesize < 1975KB and
    4 of them
}
    
rule cffddababbdbffdaabbeceb_exe {
strings:
        $s1 = "l?JP5]*'Ce-"
        $s2 = "*V_W\"R4p,E"
        $s3 = "T=FGCr0SKL%"
        $s4 = "|9xM1&(+?RE"
        $s5 = "LoadStringW"
        $s6 = "ProgramFilesDir"
        $s7 = "IsWindowVisible"
        $s8 = "DialogBoxParamW"
        $s9 = "Not enough memory"
        $s10 = "GetModuleHandleW"
        $s11 = "DispatchMessageW"
        $s12 = "CRC failed in %s"
        $s13 = "CreateCompatibleBitmap"
        $s14 = "GetCurrentDirectoryW"
        $s15 = "SHBrowseForFolderW"
        $s16 = "OLEAUT32.dll"
        $s17 = "SetEndOfFile"
        $s18 = ">MIuHU\"x1Uh"
        $s19 = "</trustInfo>"
        $s20 = "GETPASSWORD1"
condition:
    uint16(0) == 0x5a4d and filesize < 1992KB and
    4 of them
}
    
rule bcbacddbdbebdcebfedbdcae_exe {
strings:
        $s1 = "l?JP5]*'Ce-"
        $s2 = "*V_W\"R4p,E"
        $s3 = "T=FGCr0SKL%"
        $s4 = "|9xM1&(+?RE"
        $s5 = "LoadStringW"
        $s6 = "ProgramFilesDir"
        $s7 = "IsWindowVisible"
        $s8 = "DialogBoxParamW"
        $s9 = "Not enough memory"
        $s10 = "GetModuleHandleW"
        $s11 = "DispatchMessageW"
        $s12 = "CRC failed in %s"
        $s13 = "CreateCompatibleBitmap"
        $s14 = "GetCurrentDirectoryW"
        $s15 = "SHBrowseForFolderW"
        $s16 = "OLEAUT32.dll"
        $s17 = "SetEndOfFile"
        $s18 = ">MIuHU\"x1Uh"
        $s19 = "</trustInfo>"
        $s20 = "GETPASSWORD1"
condition:
    uint16(0) == 0x5a4d and filesize < 1998KB and
    4 of them
}
    
rule adbebbaeacdfbdedfddbda_exe {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "get_IsTerminating"
        $s3 = "nana.Form1.resources"
        $s4 = "Software\\Red Gate\\"
        $s5 = "RuntimeHelpers"
        $s6 = "RuntimeFieldHandle"
        $s7 = "STAThreadAttribute"
        $s8 = "WXDO[67,nzs"
        $s9 = "?tuws~SGKyC"
        $s10 = "ProductName"
        $s11 = "c`1bra7wR=S"
        $s12 = "WzbFn'B%C6w"
        $s13 = "C@dNSMgV>DR"
        $s14 = "-+31WX@G`U "
        $s15 = "{X+AS%:@b6&"
        $s16 = "_CorExeMain"
        $s17 = "LastIndexOf"
        $s18 = "WindowStyle"
        $s19 = "TUC;^YR!vw0"
        $s20 = "VarFileInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 870KB and
    4 of them
}
    
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
    
rule eebccfbaaccfeceffcfdcefcdcabca_exe {
strings:
        $s1 = "_[Xg`\\ld_shba\\Y"
        $s2 = "XXZ``dggknnruvx{{"
        $s3 = "a*rZ w$-+4_"
        $s4 = "qtkps;MX4Qf"
        $s5 = "%Wj4C)lqh_V"
        $s6 = "\"q(wv}H8l~"
        $s7 = "G`htT9)k[2A"
        $s8 = "in.\"Y+}CZH"
        $s9 = "LoadStringW"
        $s10 = ":I#M%$ty\"L"
        $s11 = "\"uVT8Ez*~G"
        $s12 = "V:g(8CzJD;m"
        $s13 = "ProgramFilesDir"
        $s14 = "IsWindowVisible"
        $s15 = "DialogBoxParamW"
        $s16 = "Not enough memory"
        $s17 = "GetModuleHandleW"
        $s18 = "DispatchMessageW"
        $s19 = "CRC failed in %s"
        $s20 = "CreateCompatibleBitmap"
condition:
    uint16(0) == 0x5a4d and filesize < 2028KB and
    4 of them
}
    
rule afafefaaeecbdaaaeadd_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "MT-C 894520"
        $s3 = "g3?7fcGD1h;"
        $s4 = "N>=y1BZ\"@O"
        $s5 = "Z_}uL1[tpSm"
        $s6 = "c>]Y%?DGBnU"
        $s7 = "Ok}Uob;1e&<"
        $s8 = ")$67yk?wnpF"
        $s9 = "!8h,jW0C2:)"
        $s10 = "FoldStringW"
        $s11 = "Yf<IR!si|:."
        $s12 = "R\"f&5,-@Ch"
        $s13 = "*796jt~[;le"
        $s14 = "i.8-xTtX$f@"
        $s15 = "`u#)\"XVq:f"
        $s16 = "|< 5T]@x^IG"
        $s17 = "lJR.\"aWvbe"
        $s18 = "BuF_\"URw#C"
        $s19 = "]/(1q8>a*#K"
        $s20 = "@TFscq[(P2;"
condition:
    uint16(0) == 0x5a4d and filesize < 3554KB and
    4 of them
}
    
rule bbfceadcefccccbdffeadaeecad_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "NetSupport Ltd1"
        $s4 = "FileDescription"
        $s5 = "GetModuleHandleW"
        $s6 = "PrivateBuild"
        $s7 = "    </security>"
        $s8 = "Greater Manchester1"
        $s9 = "LegalTrademarks"
        $s10 = "ExitProcess"
        $s11 = "</assembly>"
        $s12 = "KERNEL32.dll"
        $s13 = "SpecialBuild"
        $s14 = "Jersey City1"
        $s15 = "Peterborough1"
        $s16 = "OriginalFilename"
        $s17 = "client32.exe"
        $s18 = "VS_VERSION_INFO"
        $s19 = "Translation"
        $s20 = "CompanyName"
condition:
    uint16(0) == 0x5a4d and filesize < 114KB and
    4 of them
}
    
rule bdcbdfcadcfdedffabceecfdb_exe {
strings:
        $s1 = "ExitProcess"
        $s2 = "KERNEL32.dll"
        $s3 = "VirtualAlloc"
        $s4 = "AXAX^YZAXAYAZH"
        $s5 = "AQAPRQVH1"
        $s6 = "PAYLOAD:"
        $s7 = "VPAPAPAPI"
        $s8 = "`.rdata"
        $s9 = "Rich}E"
        $s10 = "@.mkxe"
        $s11 = "ws2_32"
        $s12 = "XAYZH"
        $s13 = ".text"
        $s14 = "APAPH"
        $s15 = "WWWM1"
condition:
    uint16(0) == 0x5a4d and filesize < 12KB and
    4 of them
}
    