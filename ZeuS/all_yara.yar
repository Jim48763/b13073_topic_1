import pe
rule eaeaecdbccdbffadfeccfbccdeea_exe {
strings:
        $s1 = "GetSystemPowerStatus"
        $s2 = "CertOpenSystemStoreW"
        $s3 = "CryptReleaseContext"
        $s4 = "CoInitializeEx"
        $s5 = "GetUserNameExW"
        $s6 = "VolumeSerialNumber"
        $s7 = "9*929:9@9G9M9S9[96:O=n=7>>>t>"
        $s8 = "Xv`gseGkoiZ"
        $s9 = "ub%+X*&Y/,("
        $s10 = "Company: %s"
        $s11 = "id74.#&1>)+"
        $s12 = ":(1;ex|)Vn,"
        $s13 = "hvnc_module"
        $s14 = "WSAGetLastError"
        $s15 = "Process32FirstW"
        $s16 = "text/javascript"
        $s17 = "HttpEndRequestA"
        $s18 = "Accept-Encoding"
        $s19 = "*/wp-login.php*"
        $s20 = "Win32_DiskDrive"
condition:
    uint16(0) == 0x5a4d and filesize < 285KB and
    4 of them
}
    
rule abcbebfadadabfafbcdad_exe {
strings:
        $s1 = "MenuItemFromPoint"
        $s2 = "GetSystemPowerStatus"
        $s3 = "CertOpenSystemStoreW"
        $s4 = "CryptReleaseContext"
        $s5 = "CoInitializeEx"
        $s6 = "GetUserNameExW"
        $s7 = "it}aVno{qlO"
        $s8 = "Product: %s"
        $s9 = "Company: %s"
        $s10 = " 02531t?;-9"
        $s11 = ")Ohcuivkm~#"
        $s12 = "Process32FirstW"
        $s13 = "text/javascript"
        $s14 = "HttpEndRequestA"
        $s15 = "Accept-Encoding"
        $s16 = "QueryDosDeviceW"
        $s17 = "InternetCrackUrlA"
        $s18 = "ReadProcessMemory"
        $s19 = "SetThreadPriority"
        $s20 = "SetFilePointerEx"
condition:
    uint16(0) == 0x5a4d and filesize < 226KB and
    4 of them
}
    
rule bfcafcbfcecfadccdab_exe {
strings:
        $s1 = "Capsulized7"
        $s2 = "ProductName"
        $s3 = "c&D(3T+5I;E"
        $s4 = "VarFileInfo"
        $s5 = "FileDescription"
        $s6 = "Leucopyrite7"
        $s7 = "Proceedings8"
        $s8 = "Pozostalych2"
        $s9 = "Prevailment8"
        $s10 = "Eastliberty2"
        $s11 = "Dihexagonal2"
        $s12 = "Mensuralist0"
        $s13 = "Stackencloud"
        $s14 = "Anisometrope8"
        $s15 = "Reticularian7"
        $s16 = "MethCallEngine"
        $s17 = "SizeofResource"
        $s18 = "5]t%)gFJ\""
        $s19 = "+.&g-fR3oG"
        $s20 = "EUPzwDI?`F"
condition:
    uint16(0) == 0x5a4d and filesize < 517KB and
    4 of them
}
    
rule bccfebebadbfeeecbfdbdfbcd_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TInterfacedPersistent"
        $s3 = "CoAddRefServerProcess"
        $s4 = "ImmSetCompositionFontA"
        $s5 = "GetEnhMetaFilePaletteEntries"
        $s6 = "CoInitializeEx"
        $s7 = "OnMouseWheelUp"
        $s8 = "SetWindowTheme"
        $s9 = "CoCreateInstanceEx"
        $s10 = "TContextPopupEvent"
        $s11 = "fsStayOnTop"
        $s12 = "OnDrawItem|"
        $s13 = "TBrushStyle"
        $s14 = "LoadStringA"
        $s15 = "GetWindowDC"
        $s16 = "TMenuMeasureItemEvent"
        $s17 = "TCanResizeEvent"
        $s18 = "ParentShowHintt"
        $s19 = "TResourceStream"
        $s20 = "GetKeyboardType"
condition:
    uint16(0) == 0x5a4d and filesize < 741KB and
    4 of them
}
    
rule bebdabafcaedcadebadfdfcaabef_exe {
strings:
        $s1 = "AutoPropertyValue"
        $s2 = "RuntimeHelpers"
        $s3 = "0hA|Q|'vBjOn^|"
        $s4 = "MakeDrawBitmap"
        $s5 = "AuthenticationMode"
        $s6 = "STAThreadAttribute"
        $s7 = "DesignerGeneratedAttribute"
        $s8 = "|.Zztg+R<1I"
        $s9 = "PictureBox1"
        $s10 = "U\"~M39v2EP"
        $s11 = "ProductName"
        $s12 = "R\"v'EP.Km~"
        $s13 = "_CorExeMain"
        $s14 = "(E)xit Game"
        $s15 = "VarFileInfo"
        $s16 = "d<rw%t2bA@L"
        $s17 = "*qlJ-{TtW29"
        $s18 = "ThreadStaticAttribute"
        $s19 = "FileDescription"
        $s20 = "set_MinimizeBox"
condition:
    uint16(0) == 0x5a4d and filesize < 927KB and
    4 of them
}
    
rule cfaddddccaffffdbfdeddfedcedbaed_exe {
strings:
        $s1 = "aVc;{xUQWRSxWWgWG"
        $s2 = "tH8N:vu[]B="
        $s3 = "Jgm`bpatvWS"
        $s4 = "CKPx|kYS3~9"
        $s5 = ",2zvlhL9M<S"
        $s6 = "_NTqlRcyzwu"
        $s7 = "QDC76_2U8PK"
        $s8 = "1BHm}8V_Q7K"
        $s9 = "YiE9o0U;Okt"
        $s10 = "XeCm]jukiTo"
        $s11 = "bptWl_jHrad"
        $s12 = "#Po4xIy8HXL"
        $s13 = ")H:z6M}Omv8"
        $s14 = "-7y6;GQ:<`c"
        $s15 = "+2qTdm^I:Ja"
        $s16 = "{Bl^xycQDJf"
        $s17 = "*PnXxwWSYt}"
        $s18 = "Zw_YyIngM~i"
        $s19 = "/TBSms6]KMN"
        $s20 = "zlDX{MjJ_Ec"
condition:
    uint16(0) == 0x5a4d and filesize < 204KB and
    4 of them
}
    
rule faeaffbdfafddeaaacffab_exe {
strings:
        $s1 = "OnContextPopup,IC"
        $s2 = "clInactiveCaption"
        $s3 = "msctls_progress32"
        $s4 = "msctls_trackbar32"
        $s5 = "TInterfacedPersistent"
        $s6 = "GetEnhMetaFilePaletteEntries"
        $s7 = "TShortCutEvent"
        $s8 = "OnMouseWheelUp"
        $s9 = "EExternalException"
        $s10 = "TContextPopupEvent"
        $s11 = " T:VY)yq%tP"
        $s12 = "TPrintScale"
        $s13 = "DragKindTEC"
        $s14 = "clBtnShadow"
        $s15 = "TOpenDialog"
        $s16 = "wqliefca_YT"
        $s17 = "fsStayOnTop"
        $s18 = "TOFNotifyEx"
        $s19 = "cG4{)F.1KMZ"
        $s20 = "MaxWidthHFC"
condition:
    uint16(0) == 0x5a4d and filesize < 830KB and
    4 of them
}
    
rule feaccaabcaaccbeabeb_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "<EX;:\"j3X}K}"
        $s4 = "GetSystemTimeAsFileTime"
        $s5 = "Y nBsHLKi|"
        $s6 = "mN <FuIOjP"
        $s7 = "Ynq>u/Ce*I"
        $s8 = "Dd}V\">Iu#"
        $s9 = "\" k3.#DB*"
        $s10 = "ExitProcess"
        $s11 = "Piriform Ltd"
        $s12 = "FindMediaType"
        $s13 = "GetProcAddress"
        $s14 = "OriginalFilename"
        $s15 = "VirtualAlloc"
        $s16 = "CreateProcessA"
        $s17 = "BP%L\\iD-c"
        $s18 = "qpGo\\&Kr|"
        $s19 = "Translation"
        $s20 = "LoadLibraryA"
condition:
    uint16(0) == 0x5a4d and filesize < 1002KB and
    4 of them
}
    
rule ceaaeadefdbcefccefaada_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "OleLoadFromStream"
        $s3 = "FreeUserPhysicalPages"
        $s4 = "CoAddRefServerProcess"
        $s5 = "GetFileAttributesExA"
        $s6 = "OpenWindowStationW"
        $s7 = "aULcn_`vo?D"
        $s8 = "kW>m-3niq8%"
        $s9 = "K(I0Hhf:ai!"
        $s10 = "+g0m)J61#P,"
        $s11 = "RKc,`o_'b3t"
        $s12 = "DtM96mI(EeR"
        $s13 = "DialogBoxParamW"
        $s14 = "ft!XncTdTnLang)"
        $s15 = "GetThreadLocale"
        $s16 = "GetHookInterface"
        $s17 = "GetConsoleWindow"
        $s18 = "GetModuleHandleA"
        $s19 = "hRA~hJAvhBAnh:Afh2A^h*AVh\"ANh"
        $s20 = "CoCreateObjectInContext"
condition:
    uint16(0) == 0x5a4d and filesize < 326KB and
    4 of them
}
    
rule adcedbcfebdaebbebecc_exe {
strings:
        $s1 = "Y#:T`ykB0%O"
        $s2 = "\"I x+m0Vwb"
        $s3 = "LoadStringA"
        $s4 = "GetKeyboardType"
        $s5 = "GetThreadLocale"
        $s6 = "WinHttpCreateUrl"
        $s7 = "GetModuleHandleA"
        $s8 = "GetSystemPaletteEntries"
        $s9 = "GetCurrentThreadId"
        $s10 = "GetLocalTime"
        $s11 = "SetEndOfFile"
        $s12 = "GetTickCount"
        $s13 = "J/JUacwyg\\{K"
        $s14 = "IsBadWritePtr"
        $s15 = "FormatMessageA"
        $s16 = "LoadLibraryExA"
        $s17 = "InterlockedDecrement"
        $s18 = "RegOpenKeyExA"
        $s19 = "GetDeviceCaps"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 3833KB and
    4 of them
}
    
rule beacdedeefdcbfdabdfadddeab_exe {
strings:
        $s1 = "jfjckjk9h hPo[o m+m"
        $s2 = "Bomv`js+Ememyd"
        $s3 = "ProductName"
        $s4 = "VarFileInfo"
        $s5 = "&vHNWF@\":2"
        $s6 = "FileDescription"
        $s7 = "TerminateProcess"
        $s8 = "WriteProcessMemory"
        $s9 = "\"16+)26m85:"
        $s10 = "Q+)wGVW\\E[L"
        $s11 = "\"$DCV@jDES_"
        $s12 = "RegEnumKeyExW"
        $s13 = "MakeSelfRelativeSD"
        $s14 = "\"S%$<!\"B  i4"
        $s15 = "LoadLibraryExA"
        $s16 = "SamCloseHandle"
        $s17 = "RegCreateKeyExW"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "OpenThreadToken"
        $s20 = "@g~hwyr{'<"
condition:
    uint16(0) == 0x5a4d and filesize < 6072KB and
    4 of them
}
    
rule ceafebdecffffafcbccfe_exe {
strings:
        $s1 = "Svt_q{b:Ltlthm"
        $s2 = "CoInitializeEx"
        $s3 = "RegSetValueExW"
        $s4 = "ProductName"
        $s5 = "hk]tYI{EBV@"
        $s6 = "@,OAbWT}6x "
        $s7 = "VarFileInfo"
        $s8 = "5InterlockedDecrement"
        $s9 = "DialogBoxParamW"
        $s10 = "FileDescription"
        $s11 = "H7DecodePointer"
        $s12 = "'GetSystemTimeAsFileTime"
        $s13 = "SetupFindNextLine"
        $s14 = "RemoveDirectoryW"
        $s15 = "DispatchMessageW"
        $s16 = "GetComputerNameW"
        $s17 = "GetCurrentThreadId"
        $s18 = "GetLocalTime"
        $s19 = "lDestroyIcon"
        $s20 = "*MoveFileExW"
condition:
    uint16(0) == 0x5a4d and filesize < 179KB and
    4 of them
}
    
rule dafbeeaebfddafdeafcaccdebdadbacc_exe {
strings:
        $s1 = "LoadStringA"
        $s2 = "GetKeyboardType"
        $s3 = "GetThreadLocale"
        $s4 = "GetModuleHandleA"
        $s5 = "GetSystemPaletteEntries"
        $s6 = "GetCurrentThreadId"
        $s7 = "GetLocalTime"
        $s8 = "SetEndOfFile"
        $s9 = "GetTickCount"
        $s10 = "FormatMessageA"
        $s11 = "LoadLibraryExA"
        $s12 = "InterlockedDecrement"
        $s13 = "GetDeviceCaps"
        $s14 = "RegOpenKeyExA"
        $s15 = "VirtualProtect"
        $s16 = "]fvF6[<pSU"
        $s17 = "L?@1_pFQj0"
        $s18 = "xc\"er'Fil"
        $s19 = "GetCurrentProcess"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 3685KB and
    4 of them
}
    
rule dcfcccbaedeeedfdeebccb_exe {
strings:
        $s1 = "mbE\"c&ga$-"
        $s2 = "ProductName"
        $s3 = "E\"X<$=;#}5"
        $s4 = "&,'LCGJAN@/"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "PoC%Bpui!ix3"
        $s8 = "7#2+/@)60e/1"
        $s9 = "PrivateBuild"
        $s10 = "qlfuqfv`vFI[ZFB"
        $s11 = "VirtualProtect"
        $s12 = "LegalTrademarks"
        $s13 = "Build Date"
        $s14 = "?FATBYWXQ&"
        $s15 = "S`anw9HhAr"
        $s16 = "(bg)lN9WR0"
        $s17 = "P,qu;'di0v"
        $s18 = "C<DlSt6kBA"
        $s19 = "$9:?)/(&'1"
        $s20 = "9RkK8V\"eo"
condition:
    uint16(0) == 0x5a4d and filesize < 261KB and
    4 of them
}
    
rule dcebeafdbcbafdfbf_exe {
strings:
        $s1 = "[|lbxllz*Ckglfhnx"
        $s2 = "GetBestInterfaceEx"
        $s3 = "ProductName"
        $s4 = " ]Q3uqKH7@x"
        $s5 = "VarFileInfo"
        $s6 = "B8:dTEDOVH_"
        $s7 = "QVWTUZ[X@y~"
        $s8 = "9*-ftu|+ms&"
        $s9 = "7Vsywyytv>G|xtm"
        $s10 = "FileDescription"
        $s11 = "gLTKPMLO GLV`N`"
        $s12 = "TerminateProcess"
        $s13 = "=r{+:=(.:&(~ 7':"
        $s14 = "WriteProcessMemory"
        $s15 = "Pvbz`zdtWkyp"
        $s16 = "aCAJGgLVqC0u"
        $s17 = "RegEnumKeyExW"
        $s18 = "QAuHU-& pGQGV"
        $s19 = "MakeSelfRelativeSD"
        $s20 = "xkl7ytutwypp`9"
condition:
    uint16(0) == 0x5a4d and filesize < 8312KB and
    4 of them
}
    
rule bbbdcafffbfefdadaefaaeefbcce_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "FileDescription"
        $s4 = "GetModuleHandleA"
        $s5 = "PrivateBuild"
        $s6 = "WmnzY8WMa5|r"
        $s7 = "OpenFileMappingA"
        $s8 = "VirtualProtect"
        $s9 = "SizeofResource"
        $s10 = "LegalTrademarks"
        $s11 = "={e)(tPX<@"
        $s12 = "w?}'1B4ayr1"
        $s13 = "_XcptFilter"
        $s14 = "SpecialBuild"
        $s15 = "KERNEL32.dll"
        $s16 = "_adjust_fdiv"
        $s17 = "__getmainargs"
        $s18 = "OriginalFilename"
        $s19 = "H!fm_8q\"j\\"
        $s20 = "VirtualAlloc"
condition:
    uint16(0) == 0x5a4d and filesize < 209KB and
    4 of them
}
    
rule fdaeeaffeebadddcddfad_exe {
strings:
        $s1 = "NfEwtJlA+]W"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "           </requestedPrivileges>"
        $s6 = "_rvoke<Arrays"
        $s7 = "VirtualProtect"
        $s8 = "CxxLongjEUnwxd"
        $s9 = "FkCDZ^uE*`"
        $s10 = "Copyright "
        $s11 = "1m5Z+Mr|z6"
        $s12 = "JWP(p+n_[k"
        $s13 = "I@]jkc4qHz"
        $s14 = "km0Q[i,DrB"
        $s15 = "BtAJ'n5T85("
        $s16 = "hmkAh\"0}ED"
        $s17 = "</assembly>"
        $s18 = "VP[\"hwO.Lh"
        $s19 = "Banjo Sting"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 199KB and
    4 of them
}
    
rule ebefaccdcdeceefadceccdbe_exe {
strings:
        $s1 = "6 6$6(6,6064686<6@6D6H6L6P6T6 7$7(7,7074787<7@7D7H7L7P7T7l7x7|7"
        $s2 = "TPacketAttribute "
        $s3 = "clInactiveCaption"
        $s4 = "TInterfacedPersistent"
        $s5 = "CoAddRefServerProcess"
        $s6 = "\\DATABASES\\%s\\DB INFO"
        $s7 = "'%s' is not a valid date"
        $s8 = "\\DRIVERS\\%s\\DB OPEN"
        $s9 = "GetEnhMetaFilePaletteEntries"
        $s10 = "TShortCutEvent"
        $s11 = "TFileStreamDeA"
        $s12 = "Database Login"
        $s13 = "OnMouseWheelUp"
        $s14 = "RequestLive<bA"
        $s15 = "CoCreateInstanceEx"
        $s16 = "EExternalException"
        $s17 = "TContextPopupEvent"
        $s18 = "TBlobStream"
        $s19 = "TPrintScale"
        $s20 = "clBtnShadow"
condition:
    uint16(0) == 0x5a4d and filesize < 1033KB and
    4 of them
}
    
rule edfbaadebfffefbbbedafdcddf_exe {
strings:
        $s1 = "</trustInfo>             </assembly>"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "5\"-j6N.eBL"
        $s5 = "hQM&8Z-pT7("
        $s6 = "kh#1-Fi~S;N"
        $s7 = "FileDescription"
        $s8 = "Tiled Tends Sifts"
        $s9 = "VirtualProtect"
        $s10 = "<security>"
        $s11 = "L7%N@1E ,-"
        $s12 = "DpI&Ptv$\\T"
        $s13 = "ExitProcess"
        $s14 = "           <requestedPrivileges>"
        $s15 = "GetProcAddress"
        $s16 = "OriginalFilename"
        $s17 = "VirtualAlloc"
        $s18 = "</security>      "
        $s19 = "Zoo Toby Logs Mop"
        $s20 = "p\"*I$$VL."
condition:
    uint16(0) == 0x5a4d and filesize < 258KB and
    4 of them
}
    
rule dfdddcccdebcbcdaaceffbcaa_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "DefColWidth"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "MSDataGridLib.DataGrid"
        $s7 = "WriteProcessMemory"
        $s8 = "nlL0YyV'~\\_"
        $s9 = "MSDATGRD.OCX"
        $s10 = "MSDataGridLib"
        $s11 = "Process32First"
        $s12 = "lkihygbvcf"
        $s13 = ".JZeXE}2h,"
        $s14 = "*F\"E<w/[M"
        $s15 = "RightToLeft"
        $s16 = "cmbOperator"
        $s17 = "kernel32.DLL"
        $s18 = "ayastbesilbhelw"
        $s19 = "DllFunctionCall"
        $s20 = "RtlMoveMemory"
condition:
    uint16(0) == 0x5a4d and filesize < 209KB and
    4 of them
}
    
rule aeeafeddfbaafbebadefc_exe {
strings:
        $s1 = "EVariantBadIndexError"
        $s2 = "PrintDlgExW"
        $s3 = "LoadStringA"
        $s4 = "0123456789|"
        $s5 = "GetKeyboardType"
        $s6 = "GetThreadLocale"
        $s7 = "TResourceManager"
        $s8 = "GetModuleHandleA"
        $s9 = "GetSystemPaletteEntries"
        $s10 = "GetCurrentThreadId"
        $s11 = "GetLocalTime"
        $s12 = "EInvalidCast"
        $s13 = "TFontCharset"
        $s14 = "EOutOfMemory"
        $s15 = "FPUMaskValue"
        $s16 = "cl3DDkShadow"
        $s17 = "clBackground"
        $s18 = "TThreadList|"
        $s19 = "JOHAB_CHARSET"
        $s20 = "FormatMessageA"
condition:
    uint16(0) == 0x5a4d and filesize < 234KB and
    4 of them
}
    
rule dbffdffbccbafdbdbdbaeba_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "VarFileInfo"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleA"
        $s5 = "GetCurrentThreadId"
        $s6 = "GetTickCount"
        $s7 = "asodjhioabsdf aisuodfhpiasdf piausdhfpaiosufh"
        $s8 = "odjsfhngs dfigjbsdf gisjdfgpjisodbfgpoijsdfng"
        $s9 = "SetHandleCount"
        $s10 = "CorExitProcess"
        $s11 = "GetSystemTimeAsFileTime"
        $s12 = "InterlockedDecrement"
        $s13 = "Kuyagupejage jiku"
        $s14 = "VirtualProtect"
        $s15 = "g#Zp,~J3ru"
        $s16 = "z_W@\"'eG6"
        $s17 = "M@/=d W,<V"
        $s18 = "GetCurrentProcess"
        $s19 = "IsDebuggerPresent"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 246KB and
    4 of them
}
    
rule dccfdfafdcccadfadedbabbddefbf_exe {
strings:
        $s1 = "503121E394D83E12E210A5FB"
        $s2 = "81CE52977E1154CE7E1ED1E43906B"
        $s3 = "Tip of the Day"
        $s4 = "09D06F7E95C609F554D709377880057E95C6EEB"
        $s5 = "pIwnByU\"[L"
        $s6 = "o'BdZ0<Uku6"
        $s7 = "HotTracking"
        $s8 = "+4iod(^=9`u"
        $s9 = "1|k@yBRm4Ho"
        $s10 = "MSComctlLib"
        $s11 = "ProductName"
        $s12 = "Ur1Of|e9L_4"
        $s13 = "Rs4_o<ByUr1"
        $s14 = "RC4;K[q+Ur1"
        $s15 = ":5mo4(w=9L;"
        $s16 = "Tc+3QmodB8 "
        $s17 = "gr1:Xey_fC4"
        $s18 = "}1RBQq.>K0b"
        $s19 = "_N>IodByUr1"
        $s20 = "VarFileInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 227KB and
    4 of them
}
    
rule bfedabbccabedfedabbbfacdcaeb_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "english-caribbean"
        $s3 = "`vector destructor iterator'"
        $s4 = "Votre logiciel est bien "
        $s5 = "CoInitializeEx"
        $s6 = "Runtime Error!"
        $s7 = "invalid string position"
        $s8 = "GetConsoleOutputCP"
        $s9 = "ser_recv(): read error: %s"
        $s10 = "Song Title:"
        $s11 = "ProductName"
        $s12 = "LC_MONETARY"
        $s13 = "VarFileInfo"
        $s14 = "JezikROmogu"
        $s15 = "Gekaufte Lizenz"
        $s16 = "DialogBoxParamA"
        $s17 = "How To Compare:"
        $s18 = "english-jamaica"
        $s19 = "`local vftable'"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 383KB and
    4 of them
}
    
rule efdccecefffeaecaebcfff_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "(NdoooomomoZZdPomomNNWNjLNNttwommiihmhjjhcN("
        $s3 = "CoInitializeEx"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "GetConsoleOutputCP"
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "DeviceIoControl"
        $s10 = "DialogBoxParamA"
        $s11 = "`local vftable'"
        $s12 = "HttpEndRequestW"
        $s13 = "FileDescription"
        $s14 = "TerminateProcess"
        $s15 = "DrawFrameControl"
        $s16 = "GetModuleHandleA"
        $s17 = "9#p:9#p:9#_nextafter"
        $s18 = "46:::>:4:>A>@>A>AAHGDHHMIMTMMTTTTW6"
        $s19 = "CreateCompatibleDC"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 337KB and
    4 of them
}
    
rule effabddccddcaffeebccdbeecfa_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "WinHttpTimeToSystemTime"
        $s3 = "Runtime Error!"
        $s4 = "invalid string position"
        $s5 = "GetConsoleOutputCP"
        $s6 = "DeviceIoControl"
        $s7 = "`local vftable'"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "CreateCompatibleDC"
        $s11 = "GetCurrentThreadId"
        $s12 = "glMatrixMode"
        $s13 = "WINSPOOL.DRV"
        $s14 = "SetWindowRgn"
        $s15 = "GetTopWindow"
        $s16 = "GetTickCount"
        $s17 = "CertSetCRLContextProperty"
        $s18 = "WriteConsoleA"
        $s19 = "Process32Next"
        $s20 = "DefFrameProcA"
condition:
    uint16(0) == 0x5a4d and filesize < 328KB and
    4 of them
}
    
rule eddaccceebefbfdcdffadebe_exe {
strings:
        $s1 = "VirtualAllocEx"
        $s2 = "RtlNtStatusToDosError"
        $s3 = "4%7!&,2( :>"
        $s4 = "ke,hvf{}*)Q"
        $s5 = "lmkYpeckmvx}k.-"
        $s6 = "GetModuleHandleA"
        $s7 = "WriteProcessMemory"
        $s8 = "$>9#2\"8~;21"
        $s9 = "<_\\uKSWUj[h"
        $s10 = "wine_get_unix_file_name"
        $s11 = "SuspendThread"
        $s12 = ":089/xsv1&:?s"
        $s13 = "3!;% w75*>;9%"
        $s14 = "=y>)?-?1?5?9?=?A?E?I?M?Q?U?Y?]?a?e?i?m?q?u?y?}?"
        $s15 = "SeSecurityPrivilege"
        $s16 = "NtCreateThreadEx"
        $s17 = "IsWow64Process"
        $s18 = "iick}mTijklods"
        $s19 = "GetProcessHeap"
        $s20 = "iz~ttq}zb2pqsgq"
condition:
    uint16(0) == 0x5a4d and filesize < 103KB and
    4 of them
}
    
rule ceafbebfeeeddbfcbccc_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "`vector destructor iterator'"
        $s3 = "Directory not empty"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "No child processes"
        $s7 = "ProductName"
        $s8 = "LC_MONETARY"
        $s9 = "VarFileInfo"
        $s10 = "DeviceIoControl"
        $s11 = "english-jamaica"
        $s12 = "`local vftable'"
        $s13 = "FileDescription"
        $s14 = "GetThreadLocale"
        $s15 = "IsWindowVisible"
        $s16 = "Masters ITC Tools"
        $s17 = "spanish-venezuela"
        $s18 = "chinese-singapore"
        $s19 = "TerminateProcess"
        $s20 = "GetModuleHandleW"
condition:
    uint16(0) == 0x5a4d and filesize < 399KB and
    4 of them
}
    
rule dedaadaddfaadffdbcccddafcbfb_exe {
strings:
        $s1 = "SetConsoleOutputCP"
        $s2 = "`local vftable'"
        $s3 = "AFX_DIALOG_LAYOUT"
        $s4 = "SetFilePointerEx"
        $s5 = "TerminateProcess"
        $s6 = "WriteProfileSectionW"
        $s7 = "GetCurrentThreadId"
        $s8 = "SetEndOfFile"
        $s9 = "GetTickCount"
        $s10 = "FindFirstFileExA"
        $s11 = "GetThreadContext"
        $s12 = "MapViewOfFile"
        $s13 = "CorExitProcess"
        $s14 = "LoadLibraryExW"
        $s15 = "CreateMailslotW"
        $s16 = "`udt returning'"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "GetProcessHeap"
        $s19 = "AreFileApisANSI"
        $s20 = "\"t<k`8W!d"
condition:
    uint16(0) == 0x5a4d and filesize < 215KB and
    4 of them
}
    
rule debefbdbcddbfedadccfdcdef_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "VirtualAllocEx"
        $s3 = "CoInitializeEx"
        $s4 = "GetUserNameExW"
        $s5 = "RtlNtStatusToDosError"
        $s6 = "eax=0x%p, ebx=0x%p, edx=0x%p, ecx=0x%p, esi=0x%p, edi=0x%p, ebp=0x%p, esp=0x%p, eip=0x%p"
        $s7 = "CopyFileExW"
        $s8 = "-<.8?5+19#'"
        $s9 = "|h>79N6;mpB"
        $s10 = "I^V]lZMHW@D"
        $s11 = "InternetCrackUrlA"
        $s12 = "RemoveDirectoryW"
        $s13 = "UnregisterClassW"
        $s14 = "GetComputerNameW"
        $s15 = "DispatchMessageW"
        $s16 = "GetModuleHandleA"
        $s17 = "CreateCompatibleBitmap"
        $s18 = "WriteProcessMemory"
        $s19 = "GetLocalTime"
        $s20 = "Flags=0x%08X"
condition:
    uint16(0) == 0x5a4d and filesize < 107KB and
    4 of them
}
    
rule acddebcccabfabeceacdfdfdbddbdc_exe {
strings:
        $s1 = "cross device link"
        $s2 = "english-caribbean"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "`vector destructor iterator'"
        $s5 = "SetDefaultDllDirectories"
        $s6 = "CUGOROZOTAHUJAMIJURUKUKI"
        $s7 = "CreateIoCompletionPort"
        $s8 = "executable format error"
        $s9 = "directory not empty"
        $s10 = "result out of range"
        $s11 = "Runtime Error!"
        $s12 = "invalid string position"
        $s13 = "Locitotebosini musebu"
        $s14 = "operation canceled"
        $s15 = "LC_MONETARY"
        $s16 = "english-jamaica"
        $s17 = "`local vftable'"
        $s18 = "spanish-venezuela"
        $s19 = "chinese-singapore"
        $s20 = "SetFilePointerEx"
condition:
    uint16(0) == 0x5a4d and filesize < 298KB and
    4 of them
}
    
rule acbaabafdbfeebbdddcffffb_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "LoadStringW"
        $s3 = "TerminateProcess"
        $s4 = "DispatchMessageW"
        $s5 = "GetModuleHandleA"
        $s6 = "GetCurrentThreadId"
        $s7 = "hnRTcNlEMizz"
        $s8 = "fNSHzPtRnWtE"
        $s9 = "SetWindowPos"
        $s10 = "EcljiZCFERmN"
        $s11 = "GetTickCount"
        $s12 = "GetWindowRect"
        $s13 = "SetHandleCount"
        $s14 = "mLRhhKnvZWmKPi"
        $s15 = "    </security>"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "InterlockedDecrement"
        $s18 = "GetProcessHeap"
        $s19 = "GetMonitorInfoW"
        $s20 = "SMQTNKCUYR"
condition:
    uint16(0) == 0x5a4d and filesize < 236KB and
    4 of them
}
    
rule dadfabaadbbfcfafeeaccbf_exe {
strings:
        $s1 = "werdrtyuiopahertyu"
        $s2 = "CMP_Init_Detection"
        $s3 = "LoadStringW"
        $s4 = "@E(<g0Dr&\""
        $s5 = "CMu1h GXVet"
        $s6 = "DispatchMessageW"
        $s7 = "GetExpandedNameW"
        $s8 = "GetModuleHandleW"
        $s9 = "exrapi32.dll"
        $s10 = "WaitNamedPipeA"
        $s11 = "TraceSQLCancel"
        $s12 = "GetFileAttributesW"
        $s13 = "IsDialogMessageW"
        $s14 = "CountryRunOnce"
        $s15 = "CreateDesktopW"
        $s16 = "GetCurrentThread"
        $s17 = "GetTempPathW"
        $s18 = "CM_Add_Range"
        $s19 = "IsBadReadPtr"
        $s20 = "IsCharUpperA"
condition:
    uint16(0) == 0x5a4d and filesize < 184KB and
    4 of them
}
    
rule cadefdcbdebadcfcaeffafbde_exe {
strings:
        $s1 = ")rMVPQEHeHHKG$"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "WSAGetLastError"
        $s5 = "FileDescription"
        $s6 = "O@CWe`OG!!!K^dL"
        $s7 = "GetShortPathNameA"
        $s8 = "GetComputerNameW"
        $s9 = "SetNamedPipeHandleState"
        $s10 = "WriteProcessMemory"
        $s11 = "GetLocalTime"
        $s12 = "SetEndOfFile"
        $s13 = "(rMVPQEHbVAA$"
        $s14 = "gethostbyname"
        $s15 = "VerifyVersionInfoW"
        $s16 = "FormatMessageW"
        $s17 = ")hKE@hMFVEV]e$"
        $s18 = "SetDllDirectoryW"
        $s19 = "RRPMO/3))&&%%U`"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 194KB and
    4 of them
}
    
rule addbaddbedcdcaddfaeebcedcbed_exe {
strings:
        $s1 = "GetConsoleOutputCP"
        $s2 = "`local vftable'"
        $s3 = "SetFilePointerEx"
        $s4 = "TerminateProcess"
        $s5 = "GetCurrentThreadId"
        $s6 = "GetTickCount"
        $s7 = "FindFirstFileExA"
        $s8 = "IIDFromString"
        $s9 = "GetMenuStringW"
        $s10 = "CorExitProcess"
        $s11 = "LoadLibraryExW"
        $s12 = "CreateMailslotW"
        $s13 = "`udt returning'"
        $s14 = "GetSystemTimeAsFileTime"
        $s15 = "VirtualProtect"
        $s16 = "GetProcessHeap"
        $s17 = "IsProcessorFeaturePresent"
        $s18 = "GetCurrentProcess"
        $s19 = "7 7$7(7,7074787<7@7D7H7L7P7T7X7\\7`7d7h7l7p7t7x7|7"
        $s20 = "3 3$3(3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3"
condition:
    uint16(0) == 0x5a4d and filesize < 205KB and
    4 of them
}
    
rule ecdcadaeeaedcfabeeedcdfbb_exe {
strings:
        $s1 = "CancelButtonClick"
        $s2 = "msctls_progress32"
        $s3 = "`vector destructor iterator'"
        $s4 = "LicenseAcceptedRadio"
        $s5 = " ei muokata, vain vastaavat ikonit uusitaan."
        $s6 = "ban van!9Alkalmaznia kell az "
        $s7 = "Runtime Error!"
        $s8 = "invalid string position"
        $s9 = "Laajennettu videorender"
        $s10 = "SetConsoleCtrlHandler"
        $s11 = "GetConsoleOutputCP"
        $s12 = "vignette obsidian "
        $s13 = "cut acest logo, contacteaz"
        $s14 = "npbstNormal"
        $s15 = "Working set"
        $s16 = "glPopMatrix"
        $s17 = "`local vftable'"
        $s18 = "TRichEditViewer"
        $s19 = "%1 = Procesos PID"
        $s20 = "SetDIBitsToDevice"
condition:
    uint16(0) == 0x5a4d and filesize < 352KB and
    4 of them
}
    
rule fbdefddfabeecbfdcfbebacebc_exe {
strings:
        $s1 = "Modification Time"
        $s2 = "`vector destructor iterator'"
        $s3 = "Never open contact sheets"
        $s4 = "invalid string position"
        $s5 = "ProductName"
        $s6 = "PdhOpenLogA"
        $s7 = "EnumObjects"
        $s8 = "VarFileInfo"
        $s9 = "`local vftable'"
        $s10 = "RasDeleteEntryW"
        $s11 = "FileDescription"
        $s12 = "NetShareGetInfo"
        $s13 = "SetFilePointerEx"
        $s14 = "TerminateProcess"
        $s15 = "GetModuleHandleW"
        $s16 = "DispatchMessageA"
        $s17 = "TcOpenInterfaceW"
        $s18 = "into dated folder only"
        $s19 = "EventWriteTransfer"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 325KB and
    4 of them
}
    
rule aeaecfeedacfeccdedcffab_exe {
strings:
        $s1 = "7$ *\"'+,<:"
        $s2 = "t,WVj\"SUhX"
        $s3 = "Accept-Encoding"
        $s4 = "GetModuleHandleA"
        $s5 = "<_\\uKSWUjlh"
        $s6 = "bvfd^clmfej}"
        $s7 = "wine_get_unix_file_name"
        $s8 = "Proxy-Connection"
        $s9 = "SeSecurityPrivilege"
        $s10 = "InterlockedDecrement"
        $s11 = "If-Modified-Since"
        $s12 = "GetProcessHeap"
        $s13 = "7$ **/#$<l./-9/"
        $s14 = "D$,PVQWjzh"
        $s15 = "^NZ_M]dL[W"
        $s16 = "t Vj.^f91u"
        $s17 = "Connection: close"
        $s18 = "lvqkzjp6szy"
        $s19 = "p~fpt|h?{gy"
        $s20 = "waqHuvwpsxo"
condition:
    uint16(0) == 0x5a4d and filesize < 124KB and
    4 of them
}
    
rule ccceeeddcfadccefdebc_exe {
strings:
        $s1 = "acmDriverDetailsA"
        $s2 = "CreateColorTransformW"
        $s3 = "`vector destructor iterator'"
        $s4 = "        <td valign=\"top\">"
        $s5 = "WNetAddConnection2A"
        $s6 = "Directory not empty"
        $s7 = "RegSetValueExA"
        $s8 = "Runtime Error!"
        $s9 = "invalid string position"
        $s10 = "accDoDefaultAction"
        $s11 = "GetConsoleOutputCP"
        $s12 = "No child processes"
        $s13 = "Link Source"
        $s14 = "`local vftable'"
        $s15 = "GetThreadLocale"
        $s16 = "&iacute; a snadn"
        $s17 = "TerminateProcess"
        $s18 = "DispatchMessageA"
        $s19 = "GetModuleHandleA"
        $s20 = "Operation not permitted"
condition:
    uint16(0) == 0x5a4d and filesize < 449KB and
    4 of them
}
    
rule ebdfbbfdfaffedddcedeacbfddef_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "?#C[o_*^gqH"
        $s4 = "FileDescription"
        $s5 = "COMDLG32.dll"
        $s6 = "OLEAUT32.dll"
        $s7 = "BringWindowToTop"
        $s8 = "TLM)Ke*~-G"
        $s9 = "PECompact2"
        $s10 = "T]v;R4R|8h4o"
        $s11 = "ADVAPI32.dll"
        $s12 = "GetProcAddress"
        $s13 = "OriginalFilename"
        $s14 = "VirtualAlloc"
        $s15 = "!)Yj.<*\"j"
        $s16 = "s&AZ`\"!sO"
        $s17 = "USER32.dll"
        $s18 = "VS_VERSION_INFO"
        $s19 = "CompanyName"
        $s20 = "Translation"
condition:
    uint16(0) == 0x5a4d and filesize < 208KB and
    4 of them
}
    
rule fedceecaceaeebfafafbbbcfefdb_exe {
strings:
        $s1 = "Tip of the Day"
        $s2 = "M3efA=z,L6c"
        $s3 = "ProductName"
        $s4 = "2KoHQpbvw;V"
        $s5 = ",M)<hwjWH/*"
        $s6 = "VarFileInfo"
        $s7 = "/3D;qs{B~kQ"
        $s8 = "FileDescription"
        $s9 = "CD;0;EFE;GHIIIF\\EEj;?."
        $s10 = "Lu[\\;EE\\IPQRSTUUUU;"
        $s11 = "kbyCe[8K\\f/"
        $s12 = "~~a#N]-m(vWr"
        $s13 = "Smo[cYm9sAQJ"
        $s14 = "22\"*D>`9pw]"
        $s15 = "5Fm([\\8@]b%"
        $s16 = "<XJ<gcaFpWs1"
        $s17 = "l!]L\\}%4B8e"
        $s18 = "=\\,L)KhwjWhB"
        $s19 = "{AI8z[A.nnfNp"
        $s20 = "TPW+XZ:.XhNN}"
condition:
    uint16(0) == 0x5a4d and filesize < 196KB and
    4 of them
}
    
rule beccafdaafabbeafdaebed_exe {
strings:
        $s1 = "t,WVj\"SUhX"
        $s2 = "Accept-Encoding"
        $s3 = "GetModuleHandleA"
        $s4 = "<_\\uKSWUjkh"
        $s5 = "6(45\" 0d.0,"
        $s6 = "yzdld`j}/imk"
        $s7 = "}ajwso{m>tjv"
        $s8 = "nC[ECGSPVWYO"
        $s9 = "wine_get_unix_file_name"
        $s10 = "Proxy-Connection"
        $s11 = "kNGWMPOGZjHJO"
        $s12 = "SeSecurityPrivilege"
        $s13 = "InterlockedDecrement"
        $s14 = "If-Modified-Since"
        $s15 = "iick}mTijklods"
        $s16 = "GetProcessHeap"
        $s17 = "|okaadhow'edfrd"
        $s18 = "D$,PVQWjuh"
        $s19 = "t Vj.^f91u"
        $s20 = "4,6@6@7D7H7L7P7T7X7\\7`7X<"
condition:
    uint16(0) == 0x5a4d and filesize < 122KB and
    4 of them
}
    
rule ccaeffeffecffffebeabfcaeeab_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "`vector destructor iterator'"
        $s3 = "BcImages.MainImages"
        $s4 = "CoInitializeEx"
        $s5 = "Runtime Error!"
        $s6 = "ProductName"
        $s7 = "\"t'SJ~5]?$"
        $s8 = "~(P.}\"iQC8"
        $s9 = "LC_MONETARY"
        $s10 = "bl,]03\"~M5"
        $s11 = "VarFileInfo"
        $s12 = "DialogBoxParamA"
        $s13 = "QueryDosDeviceA"
        $s14 = "english-jamaica"
        $s15 = "`local vftable'"
        $s16 = "FileDescription"
        $s17 = "spanish-venezuela"
        $s18 = "Nie zainstalowano"
        $s19 = "chinese-singapore"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 323KB and
    4 of them
}
    
rule bafccdddfaafafffcfca_exe {
strings:
        $s1 = "GetModuleFileName"
        $s2 = "/TN \"Update\\"
        $s3 = "VQQqQMIYzBhTtF"
        $s4 = "A)Rg{kfotState"
        $s5 = "VirtualAllocEx"
        $s6 = "System.ComponentMo"
        $s7 = "qEe@Cg>znM="
        $s8 = "aNEZFIrWJfK"
        $s9 = "a2rSJ4oV7Oe"
        $s10 = "NrgBoxStyle"
        $s11 = "s{y~EUX`)^8"
        $s12 = " pwoNs9A)Ze"
        $s13 = "a0x5gTZw2JV"
        $s14 = "ThreadStaticAttribute"
        $s15 = ".]oHppsentProcess"
        $s16 = "Central Anatolia1"
        $s17 = "ReadProcessMemory"
        $s18 = "InitializeComponent"
        $s19 = "uthor>  </Re"
        $s20 = "ERID]</UserI"
condition:
    uint16(0) == 0x5a4d and filesize < 234KB and
    4 of them
}
    
rule cbccbecededecfcdeeafdbfacfaed_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "VirtualAllocEx"
        $s3 = "CoInitializeEx"
        $s4 = "GetUserNameExW"
        $s5 = "RtlNtStatusToDosError"
        $s6 = "CopyFileExW"
        $s7 = "InternetCrackUrlA"
        $s8 = "RemoveDirectoryW"
        $s9 = "UnregisterClassW"
        $s10 = "GetComputerNameW"
        $s11 = "DispatchMessageW"
        $s12 = "GetModuleHandleA"
        $s13 = "CreateCompatibleBitmap"
        $s14 = "WriteProcessMemory"
        $s15 = "SetEndOfFile"
        $s16 = "GetTickCount"
        $s17 = "OLEAUT32.dll"
        $s18 = "PathSkipRootW"
        $s19 = "GdiplusStartup"
        $s20 = "RegCreateKeyExW"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
rule beaceaebaafffecfcabeefeca_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "invalid string position"
        $s3 = "ProductName"
        $s4 = "VarFileInfo"
        $s5 = "`local vftable'"
        $s6 = "FileDescription"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleA"
        $s9 = "CreateCompatibleBitmap"
        $s10 = "GetCurrentThreadId"
        $s11 = "glMatrixMode"
        $s12 = "GetLocalTime"
        $s13 = "COMDLG32.dll"
        $s14 = "GetTickCount"
        $s15 = "GetSystemInfo"
        $s16 = "PageSetupDlgA"
        $s17 = "GetWindowRect"
        $s18 = "InvalidateRect"
        $s19 = "SetHandleCount"
        $s20 = "CorExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 258KB and
    4 of them
}
    
rule babdcabffaebccffccedded_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "cmdPrevious"
        $s4 = "ib>_:atHP#W"
        $s5 = "FileDescription"
        $s6 = "q^^UV_PP_`;abcc\\cP"
        $s7 = "KJKUyh^ysz2{B"
        $s8 = "MethCallEngine"
        $s9 = ":)Gw5aJ.4{"
        $s10 = "SDQJ51tTmd"
        $s11 = "Xr_'0BGg`$"
        $s12 = "adoPrimaryRS"
        $s13 = "DllFunctionCall"
        $s14 = "Enter the coeffecient"
        $s15 = "OriginalFilename"
        $s16 = "GetFileName1"
        $s17 = ".:8;<;=>?@"
        $s18 = "picStatBox"
        $s19 = "VBInternal"
        $s20 = "Expression"
condition:
    uint16(0) == 0x5a4d and filesize < 184KB and
    4 of them
}
    
rule cbeabafabadcabdabadefabac_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "GetSystemPowerStatus"
        $s3 = "Runtime Error!"
        $s4 = "invalid string position"
        $s5 = "ProductName"
        $s6 = "\"1'%4!z7L:"
        $s7 = "#2 +%4!y6L9"
        $s8 = "VarFileInfo"
        $s9 = "v!xD~sU)-7("
        $s10 = "\"7F_-EjXVO"
        $s11 = "&6#*%3 m4K8"
        $s12 = "`local vftable'"
        $s13 = "FileDescription"
        $s14 = "phoneGetStatusA"
        $s15 = "SetDIBitsToDevice"
        $s16 = "DispatchMessageA"
        $s17 = "TerminateProcess"
        $s18 = "GetModuleHandleA"
        $s19 = "GetCurrentThreadId"
        $s20 = "PrivateBuild"
condition:
    uint16(0) == 0x5a4d and filesize < 253KB and
    4 of them
}
    
rule dbefeadeefdadacdfaeafdefcbe_exe {
strings:
        $s1 = "ReadProcessMemory"
        $s2 = "DllGetClassObject"
        $s3 = "ShellMessageBoxA"
        $s4 = "GetModuleHandleA"
        $s5 = "SHBrowseForFolderW"
        $s6 = "GetLocalTime"
        $s7 = "AuthzFreeContext"
        $s8 = "Ctl3dRegister"
        $s9 = "OpenJobObjectW"
        $s10 = "Q'+Vs9-<y@"
        $s11 = "CreateDirectoryW"
        $s12 = "SHGetMalloc"
        $s13 = "yuiopas.pdb"
        $s14 = "SHCreateShellItem"
        $s15 = "CreateSemaphoreA"
        $s16 = "GetProcAddress"
        $s17 = "CreateProcessA"
        $s18 = "ShellExecuteA"
        $s19 = "OpenMutexW"
        $s20 = "Ctl3dGetVer"
condition:
    uint16(0) == 0x5a4d and filesize < 177KB and
    4 of them
}
    
rule edcdebaddeedeafffebbdf_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "`vector destructor iterator'"
        $s3 = "BcImages.MainImages"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "GetConsoleOutputCP"
        $s7 = "TUiCheckBox"
        $s8 = "ProductName"
        $s9 = "LC_MONETARY"
        $s10 = " </rdf:RDF>"
        $s11 = "VarFileInfo"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "FileDescription"
        $s15 = "spanish-venezuela"
        $s16 = "chinese-singapore"
        $s17 = "TerminateProcess"
        $s18 = "GetModuleHandleW"
        $s19 = "DispatchMessageA"
        $s20 = "&Always close all tabs"
condition:
    uint16(0) == 0x5a4d and filesize < 391KB and
    4 of them
}
    
rule fbccdfdeabbfebaaebcfbbcffbe_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "   * @param {string} str"
        $s3 = "  width: 16px;"
        $s4 = "Runtime Error!"
        $s5 = "          </paper-icon-button>"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "`local vftable'"
        $s9 = "FileDescription"
        $s10 = "NetShareGetInfo"
        $s11 = "SetDIBitsToDevice"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "IPv6 unavailable"
        $s15 = "DrawFrameControl"
        $s16 = "Image has no DIB"
        $s17 = "Not all bytes sent."
        $s18 = "      if (extensions_link)"
        $s19 = "CreateCompatibleDC"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 341KB and
    4 of them
}
    
rule cfacbfebfbfacbbeeffeeffeac_exe {
strings:
        $s1 = "TerminateProcess"
        $s2 = "GetModuleHandleA"
        $s3 = "b~uhlpdr!kui"
        $s4 = "GetThreadContext"
        $s5 = "RtlGetVersion"
        $s6 = "~kisiowkt8plv"
        $s7 = "GetProcessHeap"
        $s8 = "T~pwx@t}pjxX~xl"
        $s9 = "hZd2Q\"u01"
        $s10 = "`cwTqgreaz"
        $s11 = "IsProcessorFeaturePresent"
        $s12 = "GetCurrentThread"
        $s13 = "8?97=5*u09:"
        $s14 = ":Z)fvGNC{2v"
        $s15 = "IsDebuggerPresent"
        $s16 = "KERNEL32.dll"
        $s17 = "VirtualQuery"
        $s18 = "ADVAPI32.dll"
        $s19 = "`vdjjkl~'lgf"
        $s20 = "CryptCreateHash"
condition:
    uint16(0) == 0x5a4d and filesize < 139KB and
    4 of them
}
    
rule baadcbcdedbfeddbebcabdcfddccf_exe {
strings:
        $s1 = "MenuItemFromPoint"
        $s2 = "CreateWindowStationW"
        $s3 = "CertOpenSystemStoreW"
        $s4 = "RegSetValueExW"
        $s5 = "CoInitializeEx"
        $s6 = "GetUserNameExW"
        $s7 = "Jqsjnoh\"Ht"
        $s8 = "GetWindowDC"
        $s9 = "Accept-Encoding"
        $s10 = "InternetCrackUrlA"
        $s11 = "SetThreadPriority"
        $s12 = "RemoveDirectoryW"
        $s13 = "SetFilePointerEx"
        $s14 = "GetComputerNameW"
        $s15 = "DispatchMessageW"
        $s16 = "TerminateProcess"
        $s17 = "GetModuleHandleW"
        $s18 = "CreateCompatibleBitmap"
        $s19 = "PFXExportCertStoreEx"
        $s20 = "WriteProcessMemory"
condition:
    uint16(0) == 0x5a4d and filesize < 143KB and
    4 of them
}
    
rule fbedffbbcfddbabbfefbddd_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "bsqyqEqUquqMqmq]q}1[\"+"
        $s3 = "Directory not empty"
        $s4 = "unittest._log)"
        $s5 = "requests.__version__)"
        $s6 = "SetConsoleCtrlHandler"
        $s7 = "No child processes"
        $s8 = "[>OU6yj9SiI"
        $s9 = "h')5:L_XM?;"
        $s10 = "htB#~j5}A{k"
        $s11 = "A=m%of]\">C"
        $s12 = "@q]c$m5PSFk"
        $s13 = "s@JjuplSF|_"
        $s14 = "3iza>1y|QV/"
        $s15 = ")kZ\"4-0$.F"
        $s16 = "d}!(xKBvE&3"
        $s17 = "e;i9VIoHMwt"
        $s18 = "L?;lfIU}y#e"
        $s19 = "\"Bv[ZK1,O$"
        $s20 = "l|uW[r#{`:J"
condition:
    uint16(0) == 0x5a4d and filesize < 13833KB and
    4 of them
}
    
rule ecceafbcaedcfafecdaddb_exe {
strings:
        $s1 = "!_Reporting"
        $s2 = "GetModuleHandleA"
        $s3 = "z\\8=EYA.w ("
        $s4 = "wZDAM<8aG`"
        $s5 = "Y3r0L&OX~I"
        $s6 = "uD^_S6Cneg"
        $s7 = "Lv'diX#U)O"
        $s8 = "HeapDestroy"
        $s9 = "ExitProcess"
        $s10 = "KERNEL32.dll"
        $s11 = "GetProcAddress"
        $s12 = "BROxB|v?` "
        $s13 = "MSVCRT.dll"
        $s14 = "USER32.DLL"
        $s15 = "HeapReAlloc"
        $s16 = "MessageBoxA"
        $s17 = "CloseHandle"
        $s18 = "LoadLibraryA"
        $s19 = "CreateFileA"
        $s20 = "|SrCp}:;~"
condition:
    uint16(0) == 0x5a4d and filesize < 184KB and
    4 of them
}
    
rule beffffcdeeedfbdedddd_exe {
strings:
        $s1 = "@rI/nCB([te"
        $s2 = "ProductName"
        $s3 = "FoO pBM=dA0"
        $s4 = "LoadStringA"
        $s5 = "VarFileInfo"
        $s6 = "DeviceIoControl"
        $s7 = "DialogBoxParamA"
        $s8 = "FileDescription"
        $s9 = "8' 3i,?3s,N#J,e#"
        $s10 = "DispatchMessageA"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleA"
        $s13 = "Microsoft Corporation"
        $s14 = "GetCurrentThreadId"
        $s15 = "SHBrowseForFolderA"
        $s16 = "UpdateWindow"
        $s17 = "EnableWindow"
        $s18 = "GetTickCount"
        $s19 = "MapViewOfFile"
        $s20 = "InvalidateRect"
condition:
    uint16(0) == 0x5a4d and filesize < 183KB and
    4 of them
}
    
rule fcbfeceacabfdfcefdebfadf_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "Create a new document"
        $s3 = "Find the specified text"
        $s4 = "Cancel Preview"
        $s5 = "Activate Task List"
        $s6 = "ProductName"
        $s7 = "Large Icons"
        $s8 = "VarFileInfo"
        $s9 = "FileDescription"
        $s10 = "GetModuleHandleA"
        $s11 = "Repeat the last action"
        $s12 = "Displays items in a list."
        $s13 = " Display full pages"
        $s14 = "PrivateBuild"
        $s15 = "UpdateWindow"
        $s16 = "EnableWindow"
        $s17 = "<<OLE VERBS GO HERE>>"
        $s18 = "Previous Pane"
        $s19 = "SysTreeView32"
        $s20 = "LegalTrademarks"
condition:
    uint16(0) == 0x5a4d and filesize < 235KB and
    4 of them
}
    
rule fcaaecdbbeececcbfedcd_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "TerminateProcess"
        $s6 = "CreateJobObjectW"
        $s7 = "GetModuleHandleW"
        $s8 = "GetCurrentThreadId"
        $s9 = "B'86J@PQoV~~"
        $s10 = "GetTickCount"
        $s11 = "4HG4z&G\"IP?>"
        $s12 = "SetHandleCount"
        $s13 = "CorExitProcess"
        $s14 = ";$<f<x<$=,=A=L=\">"
        $s15 = "GetSystemTimeAsFileTime"
        $s16 = "InterlockedDecrement"
        $s17 = ":P\"[kKv+@"
        $s18 = "Tvoyu mat!"
        $s19 = "ru\"s$t<cm"
        $s20 = "Copyright "
condition:
    uint16(0) == 0x5a4d and filesize < 199KB and
    4 of them
}
    
rule efbafcdbecbddeadfccafd_exe {
strings:
        $s1 = "CallMsgFilterA"
        $s2 = "VarFileInfo"
        $s3 = "@`$\" X]iG<"
        $s4 = "RemoveDirectoryA"
        $s5 = "UnregisterClassA"
        $s6 = "GetModuleHandleW"
        $s7 = "UpdateWindow"
        $s8 = "EnableWindow"
        $s9 = "GetScrollInfo"
        $s10 = "GetWindowRect"
        $s11 = "InvalidateRect"
        $s12 = "SetWindowLongW"
        $s13 = "CreateNamedPipeA"
        $s14 = "LsaFreeReturnBuffer"
        $s15 = "RegOpenKeyExW"
        $s16 = "ClientToScreen"
        $s17 = "ScreenToClient"
        $s18 = "GJE%@M-0xB"
        $s19 = "DragObject"
        $s20 = "CreateWaitableTimerW"
condition:
    uint16(0) == 0x5a4d and filesize < 203KB and
    4 of them
}
    
rule fadceedfebbcccfdafdcce_exe {
strings:
        $s1 = "Care375bema3759to"
        $s2 = "?FreeTimerAXJDI"
        $s3 = "?AppNameExPAFPAFG"
        $s4 = "?AddFolderExDPAD"
        $s5 = "Rale9adssin83ate"
        $s6 = "?AddClassOldHPAEHPAK"
        $s7 = "?ValidateDateExWDEE"
        $s8 = "Ox6boat73709"
        $s9 = "Bask615hidti"
        $s10 = "?PutDateNewPAKPAJPAJN"
        $s11 = "?IsNotPathWHI"
        $s12 = "?HideKeyNameNewXK"
        $s13 = "?FindWidthAEDE"
        $s14 = "?GetAppNameGHHFN"
        $s15 = "?FindPenWPANPAJPAFE"
        $s16 = "compression init"
        $s17 = "GetProcessHeap"
        $s18 = "?TextOldJM"
        $s19 = "PathIsUNCA"
        $s20 = "?AddTimeExAIPAIEI"
condition:
    uint16(0) == 0x5a4d and filesize < 169KB and
    4 of them
}
    
rule afbabcfdfcbcfaaffefcdfce_exe {
strings:
        $s1 = " Nuke Yucca 2004-2009"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "oGetNumb9Fo<"
        $s6 = "VirtualProtect"
        $s7 = "TickCountN"
        $s8 = "NfoK4`@MH{"
        $s9 = "d$Sk%Gi*(o"
        $s10 = "EX\"~]pLIY"
        $s11 = "\"%Du-(=}C"
        $s12 = "gp{OpenThr@"
        $s13 = "ExitProcess"
        $s14 = "[>\\c_25u|T"
        $s15 = "GetProcAddress"
        $s16 = "OriginalFilename"
        $s17 = "VirtualAlloc"
        $s18 = "user32.dll"
        $s19 = "GetIfEntry"
        $s20 = "VS_VERSION_INFO"
condition:
    uint16(0) == 0x5a4d and filesize < 206KB and
    4 of them
}
    
rule aeabebeccfbaecfceaebfc_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "l_pq~eyb79r"
        $s5 = "(L?F<Z1h8x9"
        $s6 = "FileDescription"
        $s7 = "DispatchMessageA"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleA"
        $s10 = "GetTextExtentPoint32W"
        $s11 = "GetCurrentThreadId"
        $s12 = "CreateCompatibleDC"
        $s13 = "Full Version"
        $s14 = "COMDLG32.dll"
        $s15 = "%7\"}!_[p,;!"
        $s16 = "?~+rKp^vkzkx"
        $s17 = "GetTickCount"
        $s18 = "ItemMenuClass"
        $s19 = "InvalidateRect"
        $s20 = "SetHandleCount"
condition:
    uint16(0) == 0x5a4d and filesize < 153KB and
    4 of them
}
    
rule cedacabbeddfffcfaacedbfbeecca_exe {
strings:
        $s1 = "Directory not empty"
        $s2 = "Runtime Error!"
        $s3 = "No child processes"
        $s4 = "F|DRBHPnNd,"
        $s5 = "X\"Y$:Joc/k"
        $s6 = "VarFileInfo"
        $s7 = "Mn^b-U+h9;7"
        $s8 = ":=u->AJ?v<D"
        $s9 = "GetClusterNetInterfaceState"
        $s10 = "FileDescription"
        $s11 = "Z/h),<B@B@BPA?A!"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "Operation not permitted"
        $s15 = "GetCurrentThreadId"
        $s16 = "No locks available"
        $s17 = "S%B#0!?--L+:"
        $s18 = "Invalid seek"
        $s19 = "&:$02V0L.\","
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 223KB and
    4 of them
}
    
rule deccedbbffdbabebddaedaba_exe {
strings:
        $s1 = "NtResumeThread"
        $s2 = "RtlLockHeap"
        $s3 = "ta0<lbSzXOn"
        $s4 = "GetModuleHandleA"
        $s5 = "VirtualProtect"
        $s6 = "R&<+ZcLsrI"
        $s7 = "ExitProcess"
        $s8 = "VirtualQuery"
        $s9 = "c:\\dump.exe"
        $s10 = "GetTempPathA"
        $s11 = "RtlZeroMemory"
        $s12 = "GetProcAddress"
        $s13 = "VirtualAlloc"
        $s14 = "user32.dll"
        $s15 = "jqz%L\\I1e"
        $s16 = "MessageBoxA"
        $s17 = "CloseHandle"
        $s18 = "LoadLibraryA"
        $s19 = "kernel32.dll"
        $s20 = "C:\\file.exe"
condition:
    uint16(0) == 0x5a4d and filesize < 321KB and
    4 of them
}
    
rule afecdedebeecfeccdbcbadecf_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "}2c|OX-scKMF"
        $s3 = "*R\\{,`)z7nd"
        $s4 = "SHAutoComplete"
        $s5 = "RegOpenKeyExA"
        $s6 = "v)q;w kXJS"
        $s7 = "^X]%ySkW?b"
        $s8 = "_EFcodpbHg"
        $s9 = "H&^.C8DFT("
        $s10 = "Qwu[B5kst9s"
        $s11 = "version.dll"
        $s12 = "GetProcAddress"
        $s13 = "CoInitialize"
        $s14 = "\\0Itv5.,D"
        $s15 = "lyjQDITDf;"
        $s16 = "TranslateMessage"
        $s17 = "advapi32.dll"
        $s18 = "LoadLibraryA"
        $s19 = "shlwapi.dll"
        $s20 = "comctl32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 364KB and
    4 of them
}
    
rule bdbfddffcecdaddaefeaeb_exe {
strings:
        $s1 = "CertOpenSystemStoreW"
        $s2 = "RegSetValueExW"
        $s3 = "CoInitializeEx"
        $s4 = "GetUserNameExW"
        $s5 = "H|~rdpf)24C"
        $s6 = "w:3?*0=\"%~"
        $s7 = "=:/9)#8a$-."
        $s8 = "InternetCrackUrlA"
        $s9 = "SetThreadPriority"
        $s10 = "RemoveDirectoryW"
        $s11 = "SetFilePointerEx"
        $s12 = "GetComputerNameW"
        $s13 = "DispatchMessageW"
        $s14 = "GetModuleHandleW"
        $s15 = "CreateCompatibleBitmap"
        $s16 = "PFXExportCertStoreEx"
        $s17 = "WriteProcessMemory"
        $s18 = "RtlUserThreadStart"
        $s19 = "GetLocalTime"
        $s20 = "0'0\"*.4k/3-"
condition:
    uint16(0) == 0x5a4d and filesize < 128KB and
    4 of them
}
    
rule dcafbcffcbdbaefdafdbeaa_exe {
strings:
        $s1 = "DeviceIoControl"
        $s2 = "GetModuleHandleA"
        $s3 = "Module32Next"
        $s4 = "GetThreadContext"
        $s5 = "_XcptFilter"
        $s6 = "KERNEL32.dll"
        $s7 = "_adjust_fdiv"
        $s8 = "GetFileAttributesA"
        $s9 = "__getmainargs"
        $s10 = "_controlfp"
        $s11 = "MSVCRT.dll"
        $s12 = "VirtualFree"
        $s13 = "GetStdHandle"
        $s14 = "__setusermatherr"
        $s15 = "GlobalLock"
        $s16 = ")p</sY(j;"
        $s17 = "e1Y_{:s(#"
        $s18 = "l5^)%tS>6"
        $s19 = ":X_Ts)&W0"
        $s20 = "ResetEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 170KB and
    4 of them
}
    
rule ebbbfeabfcbefcbeecfecdfcfefef_exe {
strings:
        $s1 = "zMsM\\Fjx\\bq[@WZ"
        $s2 = "5OQX<^`PkkxOQs^w`"
        $s3 = "pHXRpSKHWSw\\ycrR"
        $s4 = "QPQG/U6\\o4\\pO[D"
        $s5 = "VOu\\RLM~Y\\NWNSv"
        $s6 = "i]`SKQfNQr:QhX"
        $s7 = "eh7iesMlqkTQne"
        $s8 = "jj]Hj7gXlNSZqM"
        $s9 = "KgnGnS{hn?^VR]"
        $s10 = "mdldiedTXPpJ<7"
        $s11 = "b>C?S<V|{~^Tbb"
        $s12 = "}Pn_wbyYJ]YhY="
        $s13 = "cznxbchsagdjashkdhkaj"
        $s14 = "TkoUTGFZGk{TqcUo~e"
        $s15 = "jgGpr[sk~{`"
        $s16 = "xL2|}OZ6Ut_"
        $s17 = "ArFTefmZJMI"
        $s18 = "NTdO:cm7Wlr"
        $s19 = "TPLuCJnOQ[]"
        $s20 = "@x~zIJyFLGf"
condition:
    uint16(0) == 0x5a4d and filesize < 137KB and
    4 of them
}
    
rule fbccabaeafebbbabaccaab_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "pi6R/a2$.je"
        $s3 = "z>0mU\"|^y]"
        $s4 = "a-q1le9d>yi"
        $s5 = "ko@GI=Fy6~r"
        $s6 = ":*~JN}p^h?E"
        $s7 = "3AC! O{g}Z."
        $s8 = "YR~?^<%>#2|"
        $s9 = "q\"_A/S8}TH"
        $s10 = "ProductName"
        $s11 = "_@~f;)nT.oG"
        $s12 = "VarFileInfo"
        $s13 = "*2$x;}Squ(a"
        $s14 = "TQ-DlC 7mw4"
        $s15 = "g:]JR^lHz/c"
        $s16 = "FileDescription"
        $s17 = "GetModuleHandleA"
        $s18 = "GetCurrentDirectoryA"
        $s19 = "CreateCompatibleDC"
        $s20 = "RT4UKM&k\\Vt"
condition:
    uint16(0) == 0x5a4d and filesize < 1595KB and
    4 of them
}
    
rule edbabaaccebeeacffcddfae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExA"
        $s4 = "J\"o6>K*x 7"
        $s5 = "ytUH*6GpN^ "
        $s6 = "vU\"h_3^;]~"
        $s7 = "Ls=@AM(fb2;"
        $s8 = ">EFSgKA2|@{"
        $s9 = "zeN{OjRf9[ "
        $s10 = "DialogBoxParamA"
        $s11 = "IsWindowVisible"
        $s12 = "GetShortPathNameA"
        $s13 = "RemoveDirectoryA"
        $s14 = "DispatchMessageA"
        $s15 = "GetModuleHandleA"
        $s16 = "SetCurrentDirectoryA"
        $s17 = "SHBrowseForFolderA"
        $s18 = "EnableWindow"
        $s19 = "Bc}v9QM#}CO3"
        $s20 = "SetWindowPos"
condition:
    uint16(0) == 0x5a4d and filesize < 1554KB and
    4 of them
}
    
rule bbdceabadeddcfddeced_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExA"
        $s4 = "RC5tG@9<]8Z"
        $s5 = "dJU!*?RBa.["
        $s6 = "y(,WdmJ8Q'C"
        $s7 = "up')I~}Yn\""
        $s8 = "Z>KjDH]F'2Y"
        $s9 = "{^ a(go/8-6"
        $s10 = "9[l/L$XW#ne"
        $s11 = "ri|=ah/X*^N"
        $s12 = "/Vo`[?im0@I"
        $s13 = "`nKbZ/i1=\""
        $s14 = "!ivm,bPHf'z"
        $s15 = "OS<\"b:.9Q("
        $s16 = "DialogBoxParamA"
        $s17 = "IsWindowVisible"
        $s18 = "GetShortPathNameA"
        $s19 = "RemoveDirectoryA"
        $s20 = "DispatchMessageA"
condition:
    uint16(0) == 0x5a4d and filesize < 1497KB and
    4 of them
}
    
rule cdfbbdeaaeddcfaefdafbbcdffd_exe {
strings:
        $s1 = "GA\\FOBukm\\xufjg"
        $s2 = ".\" \"<$7$A'\\$W$]\"a'i/"
        $s3 = "Rodpnav#qj$goo"
        $s4 = "=<B?k=u3r=~9y6"
        $s5 = "@BT'FJGOA$kkkt"
        $s6 = "MtPos10Tukgatt"
        $s7 = "RegSetValueExW"
        $s8 = "Cbp]lahl[k`dls"
        $s9 = "%~khlwh(dhicoe"
        $s10 = "j#kh`jjvnwpbir"
        $s11 = "AAA-^ULFBFAA96/*CAEB&"
        $s12 = "%vbuvctz*:aobibocu"
        $s13 = "dgiignsmmi,<tfvtkv"
        $s14 = "k{iltvtx2vxetc{ak|"
        $s15 = "Ghjpajs)Laiipl>)#a"
        $s16 = "RI#XCgLr[wV"
        $s17 = "Vz\"ame#,6G"
        $s18 = "ZHLGW'|pc`b"
        $s19 = "T`bj{f|6-+V"
        $s20 = "&Bpjr{G(KLm"
condition:
    uint16(0) == 0x5a4d and filesize < 1565KB and
    4 of them
}
    