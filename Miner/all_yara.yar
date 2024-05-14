import pe
rule efaedcbbbdacaabaaad_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "RuntimeFieldHandle"
        $s3 = "STAThreadAttribute"
        $s4 = "IsClosedIDsilRMKCR"
        $s5 = "ProductName"
        $s6 = "*7x.lUprIZ;"
        $s7 = "_CorExeMain"
        $s8 = "VarFileInfo"
        $s9 = "O]a)l>t}J0g"
        $s10 = "FileDescription"
        $s11 = "GetExportedTypes"
        $s12 = "SecurityCriticalAttribute"
        $s13 = "AssemblyTitleAttribute"
        $s14 = "IAsyncResult"
        $s15 = "IEquatable`1"
        $s16 = "Synchronized"
        $s17 = "System.Resources"
        $s18 = "StringBuilder"
        $s19 = "GeneratedCodeAttribute"
        $s20 = "ItemICWnZXWlil"
condition:
    uint16(0) == 0x5a4d and filesize < 283KB and
    4 of them
}
    
rule beaeaaafeaebacbaebc_exe {
strings:
        $s1 = "007A56C60CB686C542C5A63F4806094A4F9494B7"
        $s2 = "BrowserExtension7"
        $s3 = "pszImplementation"
        $s4 = "GetWindowsVersion"
        $s5 = "CommandLineUpdate"
        $s6 = "LEnvironmentogiEnvironmentn DatEnvironmenta"
        $s7 = "ManagementBaseObject"
        $s8 = "EnumerateDirectories"
        $s9 = "RuntimeHelpers"
        $s10 = "GetSubKeyNames"
        $s11 = "ReadFileAsText"
        $s12 = "set_HolderName"
        $s13 = "RuntimeFieldHandle"
        $s14 = "GetProcessesByName"
        $s15 = "ScanResultT"
        $s16 = "System.Linq"
        $s17 = "ProductName"
        $s18 = "DecryptBlob"
        $s19 = "GetScanArgs"
        $s20 = "profilePath"
condition:
    uint16(0) == 0x5a4d and filesize < 118KB and
    4 of them
}
    
rule cefbeeefafccdafaccfebebd_exe {
strings:
        $s1 = "DescriptionAttribute"
        $s2 = "ToolboxItemAttribute"
        $s3 = "DataGridViewPaintParts"
        $s4 = "get_ColorTypeConverter"
        $s5 = "get_SupportsSorting"
        $s6 = "RuntimeHelpers"
        $s7 = "get_InheritedStyle"
        $s8 = "RuntimeFieldHandle"
        $s9 = "STAThreadAttribute"
        $s10 = "DesignerGeneratedAttribute"
        $s11 = "ProductName"
        $s12 = "L6zZ V5iRa+"
        $s13 = "`KmY6]\"fC^"
        $s14 = "_CorExeMain"
        $s15 = "VarFileInfo"
        $s16 = "cr&Z 5K70a+"
        $s17 = "op_Equality"
        $s18 = "ThreadStaticAttribute"
        $s19 = "set_MinimizeBox"
        $s20 = "OrderedDictionary"
condition:
    uint16(0) == 0x5a4d and filesize < 626KB and
    4 of them
}
    
rule fdafdaeadeefedafceceadece_exe {
strings:
        $s1 = "H4sIAAAAAAAEAHPLL8o1BABPFCykBQAAAA=="
        $s2 = "RuntimeHelpers"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = "get_ProcessorCount"
        $s6 = "ComputeHash"
        $s7 = "get_IsAdmin"
        $s8 = "get_IsWin64"
        $s9 = "ProductName"
        $s10 = "_CorExeMain"
        $s11 = "FileDescription"
        $s12 = "get_MachineName"
        $s13 = "H4sIAAAAAAAEAAtLLSrOzM8DAF/qoXAHAAAA"
        $s14 = "Microsoft Corporation"
        $s15 = "Synchronized"
        $s16 = "H4sIAAAAAAAEAAuuLA73DzczAQCex9LCCAAAAA=="
        $s17 = "GetFolderPath"
        $s18 = "get_LocalPath"
        $s19 = "get_TotalSize"
        $s20 = "StringBuilder"
condition:
    uint16(0) == 0x5a4d and filesize < 1237KB and
    4 of them
}
    
rule ddbadcdbdcefbedfdedfabdf_exe {
strings:
        $s1 = "Sobrescribir archivo?"
        $s2 = "elite prepisati datoteko?"
        $s3 = "Een ogenblik geduld"
        $s4 = "invalid distance code"
        $s5 = "f#sax3o9kFh"
        $s6 = "W|?:*9-qtBD"
        $s7 = "w@Hc>!i#3Jf"
        $s8 = "h!FLx:1}wVs"
        $s9 = "\"370=n]yEm"
        $s10 = "a*IZf\"[4%c"
        $s11 = "+Q<\"A7@2-g"
        $s12 = "^ZG}~!(6yqK"
        $s13 = "<3TZ+G*UO_="
        $s14 = "2\"eyH!nQFB"
        $s15 = "{GdOyI|i%uK"
        $s16 = "A&{9d=p%i\""
        $s17 = "M\"EyeTj#-_"
        $s18 = "LoadStringA"
        $s19 = "GetKeyboardType"
        $s20 = "   </trustInfo>"
condition:
    uint16(0) == 0x5a4d and filesize < 2561KB and
    4 of them
}
    
rule cbacbdccbeefafeefac_exe {
strings:
        $s1 = "WinSearchChildren"
        $s2 = "SW_SHOWNOACTIVATE"
        $s3 = "GUICTRLSETGRAPHIC"
        $s4 = "UnloadUserProfile"
        $s5 = "msctls_progress32"
        $s6 = "SetDefaultDllDirectories"
        $s7 = "AUTOITCALLVARIABLE%d"
        $s8 = "msctls_statusbar321"
        $s9 = "GUICTRLCREATECONTEXTMENU"
        $s10 = "Runtime Error!"
        $s11 = "IcmpCreateFile"
        $s12 = "<\"t|<%tx<'tt<$tp<&tl<!th<otd<]t`<[t\\<\\tX<"
        $s13 = "CoCreateInstanceEx"
        $s14 = "OpenWindowStationW"
        $s15 = "EWM_GETCONTROLNAME"
        $s16 = "SOUNDSETWAVEVOLUME"
        $s17 = "~f;D$@ulIyt"
        $s18 = "Run Script:"
        $s19 = "\"Rg,wdf6IM"
        $s20 = ">Ctu^e{1_WP"
condition:
    uint16(0) == 0x5a4d and filesize < 6295KB and
    4 of them
}
    
rule cedbfdacdedfebddbfebdade_exe {
strings:
        $s1 = "terminals database is inaccessible"
        $s2 = "ASN1_IA5STRING_it"
        $s3 = "spanish-guatemala"
        $s4 = "german-luxembourg"
        $s5 = "[C]hange settings"
        $s6 = "0&1G1a1q1F4,6|6l:"
        $s7 = "API not running%s"
        $s8 = "*Thread Zero Hash"
        $s9 = "optionalSignature"
        $s10 = "UI_destroy_method"
        $s11 = "DES_read_password"
        $s12 = "[G]PU management "
        $s13 = "Only Some Reasons"
        $s14 = "encrypted track 2"
        $s15 = "PROCESS_PCI_VALUE"
        $s16 = "bad function call"
        $s17 = "cross device link"
        $s18 = "id-cmc-dataReturn"
        $s19 = "OBJECT DESCRIPTOR"
        $s20 = "english-caribbean"
condition:
    uint16(0) == 0x5a4d and filesize < 5668KB and
    4 of them
}
    
rule afdddbedbcdacfddbadccbafef_exe {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "RuntimeHelpers"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = ")[Y:nS-NCz2"
        $s6 = "7Pn0ld?@Xc2"
        $s7 = "=c1F<[bu@iA"
        $s8 = "yr4C+*QubP'"
        $s9 = "Z2+F5jfg\"%"
        $s10 = "ComputeHash"
        $s11 = ";Ql91,qobCS"
        $s12 = "op_Equality"
        $s13 = "w%=U\"zWI,a"
        $s14 = "Et)Tk\"=9j4"
        $s15 = "Ls}h#@b(8m^"
        $s16 = "VarFileInfo"
        $s17 = "Cl<+%`BL'I,"
        $s18 = "Y'x#WmJcLF{"
        $s19 = "ProductName"
        $s20 = "l>*&R9K'MUL"
condition:
    uint16(0) == 0x5a4d and filesize < 1912KB and
    4 of them
}
    
rule adaccebcadfdfaecbfdcbea_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "invalid string position"
        $s5 = "oAFzL%i=n5@"
        $s6 = "VarFileInfo"
        $s7 = "LC_MONETARY"
        $s8 = "s) .'Szt2,#"
        $s9 = "english-jamaica"
        $s10 = "`local vftable'"
        $s11 = "SetVolumeLabelA"
        $s12 = "spanish-venezuela"
        $s13 = "SetComputerNameW"
        $s14 = "GetModuleHandleA"
        $s15 = "TerminateProcess"
        $s16 = "GetCurrentDirectoryA"
        $s17 = "GetCurrentThreadId"
        $s18 = "GetLocalTime"
        $s19 = "GetTickCount"
        $s20 = "south-africa"
condition:
    uint16(0) == 0x5a4d and filesize < 553KB and
    4 of them
}
    
rule dfbabacfaededdcbcccebddaffbd_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "_CorExeMain"
        $s4 = "FileDescription"
        $s5 = "--load-extension="
        $s6 = "get_CurrentDirectory"
        $s7 = "    </security>"
        $s8 = "DebuggingModes"
        $s9 = "o=M>_}Vgwvfvvw"
        $s10 = "\\launcher.exe"
        $s11 = "LegalTrademarks"
        $s12 = "Copyright "
        $s13 = "$`>\"*nzAR"
        $s14 = "DebuggableAttribute"
        $s15 = "</assembly>"
        $s16 = "\\config.txt"
        $s17 = "set_Arguments"
        $s18 = "OriginalFilename"
        $s19 = "set_FileName"
        $s20 = "ConsoleKeyInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 199KB and
    4 of them
}
    
rule ebffffcfacfbcefbeaedbffdbdedb_exe {
strings:
        $s1 = "&submit=Submit%21"
        $s2 = "Take away all engines."
        $s3 = "OI*N|\\<Z0u\"z"
        $s4 = " khBfF;)q-i"
        $s5 = "EncryptFile"
        $s6 = "3K}\"FGk%Yf"
        $s7 = "g\"(7A0jDnd"
        $s8 = "aE\"9+bB:=}"
        $s9 = "./`x^MoPf'z"
        $s10 = "MSComctlLib"
        $s11 = "]2T\"wP&)+o"
        $s12 = "VarFileInfo"
        $s13 = "V>bq05Iu*t_"
        $s14 = "\"=]Eb!*If%"
        $s15 = "#)AmI=BF'DY"
        $s16 = "Your Email."
        $s17 = "i2+]uz)f~DR"
        $s18 = "GetShortPathNameA"
        $s19 = "GetModuleHandleA"
        $s20 = "Procentage Done:"
condition:
    uint16(0) == 0x5a4d and filesize < 2310KB and
    4 of them
}
    
rule becbecfffdbefbb_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "FileDescription"
        $s4 = "    </security>"
        $s5 = "Google Inc."
        $s6 = "</assembly>"
        $s7 = "_XcptFilter"
        $s8 = "__getmainargs"
        $s9 = "LegalTrademark"
        $s10 = "Google Chrome"
        $s11 = "_controlfp"
        $s12 = "msvcrt.dll"
        $s13 = "VS_VERSION_INFO"
        $s14 = "FileVersion"
        $s15 = "Translation"
        $s16 = "CompanyName"
        $s17 = "OpenProcess"
        $s18 = "kernel32.dll"
        $s19 = "chrome.exe"
        $s20 = "70,0,3538,110"
condition:
    uint16(0) == 0x5a4d and filesize < 5512KB and
    4 of them
}
    
rule bcfdcfaebdbfbbfedbddddcaae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "IsWindowVisible"
        $s6 = "DialogBoxParamA"
        $s7 = "GetModuleHandleA"
        $s8 = "DispatchMessageA"
        $s9 = "SHBrowseForFolderA"
        $s10 = "EnableWindow"
        $s11 = "GetTickCount"
        $s12 = "SetWindowPos"
        $s13 = "RegEnumValueA"
        $s14 = "SysListView32"
        $s15 = "GetWindowRect"
        $s16 = "IIDFromString"
        $s17 = "CloseClipboard"
        $s18 = "InvalidateRect"
        $s19 = "SHAutoComplete"
        $s20 = "LoadLibraryExA"
condition:
    uint16(0) == 0x5a4d and filesize < 261KB and
    4 of them
}
    
rule baefbeadabeacadebacf_exe {
strings:
        $s1 = "ProductName"
        $s2 = "<XBeg4 HWND"
        $s3 = "(/clr)=Rpia"
        $s4 = "/0123^89:;<"
        $s5 = "&Na!mT9vF$'"
        $s6 = "VarFileInfo"
        $s7 = " LoadSE(%u)"
        $s8 = "R\"ZXYZ[\\]^_`a"
        $s9 = "FileDescription"
        $s10 = "Microsoft Corporation"
        $s11 = "OLEAUT32.dll"
        $s12 = "WINSPOOL.DRV"
        $s13 = "?Pai\\PBcQ`s/?"
        $s14 = "VirtualProtect"
        $s15 = "PathIsUNCA"
        $s16 = "'tFa[hSbMX"
        $s17 = "08X (nIDC="
        $s18 = "v2/Qual4!W"
        $s19 = ">4`1[i9^7y"
        $s20 = "Ovw-6VQKsb"
condition:
    uint16(0) == 0x5a4d and filesize < 260KB and
    4 of them
}
    
rule cbbbdbedffecefaaaa_exe {
strings:
        $s1 = "    </security>"
        $s2 = "</assembly>"
        $s3 = "_XcptFilter"
        $s4 = "__getmainargs"
        $s5 = "_controlfp"
        $s6 = "msvcrt.dll"
        $s7 = "OpenProcess"
        $s8 = "kernel32.dll"
        $s9 = "__set_app_type"
        $s10 = "_environ"
        $s11 = "strlen"
        $s12 = "@.rsrc"
        $s13 = "@.data"
        $s14 = "__argv"
        $s15 = "memcpy"
        $s16 = "malloc"
        $s17 = "memset"
        $s18 = "Sleep"
        $s19 = ".text"
condition:
    uint16(0) == 0x5a4d and filesize < 5507KB and
    4 of them
}
    
rule cdaaacacccebeeacbdaedeadeacf_exe {
strings:
        $s1 = "Ep5/892446978580125789244697858012578924469785801257892adn"
        $s2 = "D<@1A;M=L0L1I1M8L<H1"
        $s3 = "78580Aa57(9244697:58012578924469"
        $s4 = "URL=\"file:///"
        $s5 = "n{?J1Jpm&G3JyR"
        $s6 = "NtResumeThread"
        $s7 = "RegSetValueExW"
        $s8 = ";u;q2p6t;}1q7p:p;};y2x6"
        $s9 = "l086450?=07>1=<;=8=>4=0'="
        $s10 = "!!\"..\"%&-%*&* )+m\""
        $s11 = "NtGetContextThread"
        $s12 = "vd{w?Y5p3R>"
        $s13 = "UqF=Qwtm,9P"
        $s14 = "+\"Dzt2(|j="
        $s15 = "kY0W:n7R6i!"
        $s16 = "fGt]48M>u<E"
        $s17 = "?^m<[IG1E0O"
        $s18 = "U#'6y$@OvQN"
        $s19 = "exdwtsq|azh"
        $s20 = "v3dE4ciCeZX"
condition:
    uint16(0) == 0x5a4d and filesize < 1862KB and
    4 of them
}
    