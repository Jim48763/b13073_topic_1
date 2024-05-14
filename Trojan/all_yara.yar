import pe
rule ddbacfeadffadeadecfcfce_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "WM_MDIICONARRANGE"
        $s3 = "All_Users_Startup"
        $s4 = "DescriptionAttribute"
        $s5 = "CWP_SKIPTRANSPARENT"
        $s6 = "ComboBoxStyles"
        $s7 = "FlagsAttribute"
        $s8 = "set_SizingGrip"
        $s9 = "GetHeaderOrFooterInfo"
        $s10 = "DrawStringPosition"
        $s11 = "SS_REALSIZECONTROL"
        $s12 = "STAThreadAttribute"
        $s13 = "pSearchDown"
        $s14 = "ProductName"
        $s15 = "W3fj4c`X;Jb"
        $s16 = "_CorExeMain"
        $s17 = "ComputeHash"
        $s18 = "Fi&nd what:"
        $s19 = "Adobe Inc.0"
        $s20 = "LastIndexOf"
condition:
    uint16(0) == 0x5a4d and filesize < 641KB and
    4 of them
}
    
rule ffcbefeafedefcdadfdaebb_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = ".?WX>S <w=L"
        $s3 = "G0%EHPD7pkK"
        $s4 = "ProductName"
        $s5 = "_CorExeMain"
        $s6 = "[CNXQ1\"'L$"
        $s7 = "op_Equality"
        $s8 = "lZUNFe!3/8H"
        $s9 = "f>N]Ybyd;As"
        $s10 = "boardHeight"
        $s11 = "VarFileInfo"
        $s12 = "NT\"=C(A@5t"
        $s13 = "+,4C:cp6?#["
        $s14 = "FileDescription"
        $s15 = "Node_X_Coordinate"
        $s16 = " damage points to"
        $s17 = "InitializeComponent"
        $s18 = "I'm going to move here "
        $s19 = "Dictionary`2"
        $s20 = "Synchronized"
condition:
    uint16(0) == 0x5a4d and filesize < 930KB and
    4 of them
}
    
rule efcdaabefafcbfcdacbabbf_exe {
strings:
        $s1 = "Gns*fMm`bkw"
        $s2 = "<-mil1_eofq"
        $s3 = "\\App 0chRme.exe"
        $s4 = "Z/x\"qW#e/0."
        $s5 = "SOFTWARE\\Mp"
        $s6 = "OLEAUT32.dll"
        $s7 = "w H\\:CZju@J"
        $s8 = "CryptUnprotectData"
        $s9 = "InitCommonControlsEx"
        $s10 = "    </security>"
        $s11 = "VirtualProtect"
        $s12 = "0p%x:<CLB/"
        $s13 = "[NDzS5_=cf"
        $s14 = "fPWoQkxbun"
        $s15 = "xTbAjh=#/<"
        $s16 = "@%HB$~IJue"
        $s17 = "@&H'P)X*#G"
        $s18 = "Ht?3a/P+`f"
        $s19 = "oP+OLjWeuQ"
        $s20 = "O]i<?xml T"
condition:
    uint16(0) == 0x5a4d and filesize < 360KB and
    4 of them
}
    
rule beebcbfebdadaaebbccabbcf_exe {
strings:
        $s1 = "AutoPropertyValue"
        $s2 = "Defensive rebound"
        $s3 = "SetDataGridDesign"
        $s4 = "Change chart type"
        $s5 = "Btn_AddParameters"
        $s6 = "set_Panel_Display"
        $s7 = "set_Btn_BasicInfo"
        $s8 = "TreeViewEventArgs"
        $s9 = "XmlSchemaParticle"
        $s10 = "Show me teams leaders"
        $s11 = "Move to add or update player"
        $s12 = "Choose help language"
        $s13 = "ToolboxItemAttribute"
        $s14 = "CheckPlayersParameters"
        $s15 = "CollectionChangeAction"
        $s16 = "Total PG In Hapoel Holon"
        $s17 = "Lbl_WhatManage"
        $s18 = "RuntimeHelpers"
        $s19 = "set_FixedValue"
        $s20 = "Btn_MouseLeave"
condition:
    uint16(0) == 0x5a4d and filesize < 1468KB and
    4 of them
}
    
rule eddbabfcddecdfdebafba_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TrailingTextColor"
        $s3 = "TInterfacedPersistent"
        $s4 = "CoAddRefServerProcess"
        $s5 = "ImmSetCompositionFontA"
        $s6 = "GetEnhMetaFilePaletteEntries"
        $s7 = " 2001, 2002 Mike Lischke"
        $s8 = "Database Login"
        $s9 = "CoInitializeEx"
        $s10 = "OnMouseWheelUp"
        $s11 = "ckRunningOrNew"
        $s12 = "TContextPopupEvent"
        $s13 = "TCommonCalendart+C"
        $s14 = "u0h/8msjO=:"
        $s15 = "fsStayOnTop"
        $s16 = "Medium Gray"
        $s17 = "iJ*g$Olt[Q^"
        $s18 = "TOleGraphic"
        $s19 = "TOpenDialog"
        $s20 = "X`6SRj1aNTI"
condition:
    uint16(0) == 0x5a4d and filesize < 814KB and
    4 of them
}
    
rule adadbeeeccfdfbadaabadf_dll {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "FileDescription"
        $s4 = "Microsoft Corporation"
        $s5 = "PrivateBuild"
        $s6 = "$~D;p%ZEMh]p"
        $s7 = "s.+8argu(\\{"
        $s8 = "87=7;!T%]U\\\\d'"
        $s9 = "Az~__GLOBAL_HEAP_S"
        $s10 = "VirtualProtect"
        $s11 = "Unknown excepE"
        $s12 = "LegalTrademarks"
        $s13 = "pac#f{&wi8"
        $s14 = "_5wvl71$Lg"
        $s15 = "R\"vVA+0Q<"
        $s16 = "type_infom"
        $s17 = "IK@ Cu6DAj"
        $s18 = "ihjvk\"lop"
        $s19 = "SpecialBuild"
        $s20 = "ADVAPI32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 81KB and
    4 of them
}
    
rule fdeaeacdbbccaddadad_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "_T.aVmd8k*;"
        $s4 = "__vbaStrCopy"
        $s5 = "__vbaVarTstNe"
        $s6 = "_adj_fdivr_m64"
        $s7 = "FJUMREHOVEDERS"
        $s8 = "&!% !#>\"4)"
        $s9 = "ldYrZZIm7220"
        $s10 = "ugpax\"#?u}}"
        $s11 = "__vbaLateMemSt"
        $s12 = "OriginalFilename"
        $s13 = "4#73#52#\"f2."
        $s14 = "__vbaI4Str"
        $s15 = "Moderliges"
        $s16 = "legetjsfor"
        $s17 = "Earableosc"
        $s18 = "VS_VERSION_INFO"
        $s19 = "BorderStyle"
        $s20 = "CompanyName"
condition:
    uint16(0) == 0x5a4d and filesize < 161KB and
    4 of them
}
    
rule aaccecdcadfbedbeabebbcbda_dll {
strings:
        $s1 = "NppShell Settings"
        $s2 = "Show dynamic icon"
        $s3 = "`vector destructor iterator'"
        $s4 = "CoInitializeEx"
        $s5 = "Runtime Error!"
        $s6 = "BeginBufferedPaint"
        $s7 = "_T.aVmd8k*;"
        $s8 = "VarFileInfo"
        $s9 = "DialogBoxParamW"
        $s10 = "`local vftable'"
        $s11 = "FileDescription"
        $s12 = "DllGetClassObject"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleW"
        $s15 = "Add context menu item"
        $s16 = "GetTextExtentPoint32W"
        $s17 = "CreateCompatibleDC"
        $s18 = "GetCurrentThreadId"
        $s19 = "GetTickCount"
        $s20 = "Unknown exception"
condition:
    uint16(0) == 0x5a4d and filesize < 342KB and
    4 of them
}
    
rule ccdfadefbcbccfadc_exe {
strings:
        $s1 = "-:T#?:V!?:C&<:F&=:E'=:"
        $s2 = "y#3:u6::r7::p78:~\"2:X"
        $s3 = ":S'4:g-0:h.0:r(=:z5=:"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "GetWindowDC"
        $s7 = "_T.aVmd8k*;"
        $s8 = "shellexecute=kabe.bat"
        $s9 = "MS Sans Serif\""
        $s10 = "__vbaVarLateMemSt"
        $s11 = "CreateCompatibleBitmap"
        $s12 = "GetSystemPaletteEntries"
        $s13 = "kJ)4hl[pB\\I"
        $s14 = "TdUI^Ou||{q-"
        $s15 = "FolderExists"
        $s16 = "__vbaLenBstr"
        $s17 = "USEAUTOPLAY=1"
        $s18 = "wscript.shell"
        $s19 = "__vbaErrorOverflow"
        $s20 = " :L4::AZ`:`]Q:x{{:3+.:"
condition:
    uint16(0) == 0x5a4d and filesize < 337KB and
    4 of them
}
    
rule effbdfeacaedacbffcbf_vbs {
strings:
        $s1 = "    If (char <> \" \") Then"
        $s2 = "Execute(\"vSg = \"\"\"\"\")"
        $s3 = "End Function "
        $s4 = "eQACeDnGd"
        $s5 = "EOGtnj()"
        $s6 = "    End If"
        $s7 = "XqTs = F"
        $s8 = "End Sub"
        $s9 = "End if"
        $s10 = "Next "
condition:
    uint16(0) == 0x5a4d and filesize < 7KB and
    4 of them
}
    
rule cddeafdbafedcbfefeffcfbbeedfb_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExA"
        $s4 = "2Q@$4Dy%P6x"
        $s5 = "DialogBoxParamA"
        $s6 = "GetShortPathNameA"
        $s7 = "DispatchMessageA"
        $s8 = "GetModuleHandleA"
        $s9 = "SHBrowseForFolderA"
        $s10 = "EnableWindow"
        $s11 = "GetTickCount"
        $s12 = "RegEnumValueA"
        $s13 = "SysListView32"
        $s14 = "InvalidateRect"
        $s15 = "SHAutoComplete"
        $s16 = "CloseClipboard"
        $s17 = "LoadLibraryExA"
        $s18 = "RegCreateKeyExA"
        $s19 = "CoTaskMemFree"
        $s20 = "GetDeviceCaps"
condition:
    uint16(0) == 0x5a4d and filesize < 502KB and
    4 of them
}
    
rule ddeeafbcdffcabaacefecbac_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExA"
        $s4 = "Odi^4A(@N#."
        $s5 = "DialogBoxParamA"
        $s6 = "GetShortPathNameA"
        $s7 = "DispatchMessageA"
        $s8 = "GetModuleHandleA"
        $s9 = "SHBrowseForFolderA"
        $s10 = "EnableWindow"
        $s11 = "GetTickCount"
        $s12 = "RegEnumValueA"
        $s13 = "SysListView32"
        $s14 = "InvalidateRect"
        $s15 = "SHAutoComplete"
        $s16 = "CloseClipboard"
        $s17 = "LoadLibraryExA"
        $s18 = "RegCreateKeyExA"
        $s19 = "CoTaskMemFree"
        $s20 = "GetDeviceCaps"
condition:
    uint16(0) == 0x5a4d and filesize < 293KB and
    4 of them
}
    
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
    
rule ffaddfbcadcdfdbfeffafce_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "More information at:"
        $s3 = "RegSetValueExA"
        $s4 = "DialogBoxParamA"
        $s5 = "GetShortPathNameA"
        $s6 = "DispatchMessageA"
        $s7 = "GetModuleHandleA"
        $s8 = "SHBrowseForFolderA"
        $s9 = "EnableWindow"
        $s10 = "('r:Df}.GVfA"
        $s11 = "GetTickCount"
        $s12 = "RegEnumValueA"
        $s13 = "SysListView32"
        $s14 = "InvalidateRect"
        $s15 = "SHAutoComplete"
        $s16 = "CloseClipboard"
        $s17 = "LoadLibraryExA"
        $s18 = "RegCreateKeyExA"
        $s19 = "CoTaskMemFree"
        $s20 = "GetDeviceCaps"
condition:
    uint16(0) == 0x5a4d and filesize < 454KB and
    4 of them
}
    
rule bdcccbcbfddbccdbbc_exe {
strings:
        $s1 = "%l ^l^eMdJ Yx@sMs"
        $s2 = "fvlZ _u\\p\\rH @s"
        $s3 = "PopupWindowFinder"
        $s4 = "s?\\,e,t3c<\\)h9o"
        $s5 = "EventFiringWebElement"
        $s6 = "AssemblyBuilderAccess"
        $s7 = "wrappedOptions"
        $s8 = "1fAjtWeBtEcRtY"
        $s9 = ",cMn]oH MeMa|h"
        $s10 = "EQaNlIMVnII]eT"
        $s11 = ",{,U3n<k)n9ow?n,},"
        $s12 = "LogicalCallContext"
        $s13 = ")/9sk?e,e,p3a<s)s9"
        $s14 = "ae[EGuTKzy~"
        $s15 = "x[IG]zMNEAX"
        $s16 = "3$>_^cTdsn?"
        $s17 = "@3/<s)o9rt?"
        $s18 = "xTl?vZr_iCn"
        $s19 = "'[,c3a<p)]9"
        $s20 = "XeKFErIwRlP"
condition:
    uint16(0) == 0x5a4d and filesize < 615KB and
    4 of them
}
    
rule dacfeecdccfaecaffcefee_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "set_SizingGrip"
        $s3 = "\\dagger_cheap.png"
        $s4 = "RuntimeFieldHandle"
        $s5 = "STAThreadAttribute"
        $s6 = "InternalMemberValu"
        $s7 = "DesignerGeneratedAttribute"
        $s8 = "Angelic War"
        $s9 = "_CorExeMain"
        $s10 = "set_grpInfo"
        $s11 = "ProductName"
        $s12 = "VarFileInfo"
        $s13 = "System.Linq"
        $s14 = "ThreadStaticAttribute"
        $s15 = "KeyEventHandler"
        $s16 = "set_MinimizeBox"
        $s17 = "SafeLibraryHand"
        $s18 = "set_UseWaitCursor"
        $s19 = "get_pnlInventory"
        $s20 = "_testFillPlayerSheet"
condition:
    uint16(0) == 0x5a4d and filesize < 1236KB and
    4 of them
}
    
rule aabccbbdeebdacfbfccafbeebbcbefcc_exe {
strings:
        $s1 = "rectangleAsString"
        $s2 = "StartInFullscreen"
        $s3 = "GetFileLineNumber"
        $s4 = "DefaultResolution"
        $s5 = "ContentLoaderResolver"
        $s6 = "GenerateTriggerFromType"
        $s7 = "dAgGAnBQaAIHA5BAcA8GADBAbAEGAnBQZAwEABAgEAgE"
        $s8 = "ResolveContentLoader"
        $s9 = "GetInterpolatedValue"
        $s10 = "FieldOffsetAttribute"
        $s11 = "EnqueueWorkerThread"
        $s12 = "DoesNotMatchMetaDataType"
        $s13 = "RuntimeHelpers"
        $s14 = "AppDomainSetup"
        $s15 = "ContentNameMissing"
        $s16 = "RuntimeFieldHandle"
        $s17 = "CreateLookAtMatrix"
        $s18 = "QZA0GAhBgTAQHAjBQdAQGAvBgc"
        $s19 = "AtlasRegion"
        $s20 = "_CorExeMain"
condition:
    uint16(0) == 0x5a4d and filesize < 859KB and
    4 of them
}
    
rule eadaefbbeebadaffbfdfbbbc_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = ">b:rWm89K.F"
        $s3 = "`\"h8j.t$;E"
        $s4 = ";k9h*x\"r!p"
        $s5 = "s`?~m|wr[Db"
        $s6 = "ProductName"
        $s7 = "oa~{hu4sbq."
        $s8 = "_CorExeMain"
        $s9 = "V{pefgzmu]h"
        $s10 = "}zwdq0o~mJ'"
        $s11 = "9`0,w~'n>6a"
        $s12 = ">f6n8#i1a5_"
        $s13 = "ImYQdKrvVt?"
        $s14 = "VarFileInfo"
        $s15 = "T{2ins(}dkB"
        $s16 = "FileDescription"
        $s17 = "fefabadd.Resources.resources"
        $s18 = "Synchronized"
        $s19 = "FpZD`|vpEKay"
        $s20 = "X{tzB-f;d\\4"
condition:
    uint16(0) == 0x5a4d and filesize < 672KB and
    4 of them
}
    
rule fddaeadaeabcabfddaeedcefc_exe {
strings:
        $s1 = "Ty 2Q-%L YEo TqR "
        $s2 = "cxnme\\tcoU WoWnHee"
        $s3 = "RuntimeHelpersRuntimeHelpers"
        $s4 = "RuntimeHelpers"
        $s5 = "Q$sJlNt[_Otvt2"
        $s6 = "FVloSBsSeSIRfx"
        $s7 = "; Fr[ Roc vnVq"
        $s8 = "CooLeIlRpEo_rX"
        $s9 = "Y^K[_cf[*rS[Qd"
        $s10 = "cSekr]f'bWnXee"
        $s11 = "CTUIiPiHivljzZ"
        $s12 = "rrdFnJmorZtBW>"
        $s13 = "ol!UyeI nD>"
        $s14 = "SFLzC^ UaJe"
        $s15 = "tEpr=!WVn92"
        $s16 = "?Cxe_RBaZA<"
        $s17 = ">Lea_MBnKW<"
        $s18 = "yeO_waZdUnp"
        $s19 = "I)h0r+t.a?d"
        $s20 = "PaSfer_1=0&"
condition:
    uint16(0) == 0x5a4d and filesize < 572KB and
    4 of them
}
    
rule eeabeabadeacbecdefeceda_exe {
strings:
        $s1 = "$INDEX_ALLOCATION"
        $s2 = "RegSetValueExW"
        $s3 = "SeLoadDriverPrivilege"
        $s4 = "QueryServiceStatus"
        $s5 = "DeviceIoControl"
        $s6 = "PathAddBackslashW"
        $s7 = "SetThreadPriority"
        $s8 = "SetFilePointerEx"
        $s9 = "GetModuleHandleW"
        $s10 = "ntoskr_nl.ex"
        $s11 = "Specif_yCach"
        $s12 = "CY-HE 4194690"
        $s13 = "RegEnumKeyExW"
        $s14 = "VerifyVersionInfoW"
        $s15 = "$REPARSE_POINT"
        $s16 = "ControlService"
        $s17 = "OpenSCManagerW"
        $s18 = "$EA_INFORMATION"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "OpenProcessToken"
condition:
    uint16(0) == 0x5a4d and filesize < 119KB and
    4 of them
}
    
rule cdadccfeabeeaefdededfdac_exe {
strings:
        $s1 = "$INDEX_ALLOCATION"
        $s2 = "RegSetValueExW"
        $s3 = "SeLoadDriverPrivilege"
        $s4 = "QueryServiceStatus"
        $s5 = "DeviceIoControl"
        $s6 = "PathAddBackslashW"
        $s7 = "SetThreadPriority"
        $s8 = "SetFilePointerEx"
        $s9 = "GetModuleHandleW"
        $s10 = "ntoskr_nl.ex"
        $s11 = "Specif_yCach"
        $s12 = "CY-HE 4194690"
        $s13 = "RegEnumKeyExW"
        $s14 = "VerifyVersionInfoW"
        $s15 = "$REPARSE_POINT"
        $s16 = "ControlService"
        $s17 = "OpenSCManagerW"
        $s18 = "$EA_INFORMATION"
        $s19 = "GetFileAttributesW"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 119KB and
    4 of them
}
    
rule bceefecaeefbffadbcbeadbfd_exe {
strings:
        $s1 = "$INDEX_ALLOCATION"
        $s2 = "RegSetValueExW"
        $s3 = "SeLoadDriverPrivilege"
        $s4 = "QueryServiceStatus"
        $s5 = "DeviceIoControl"
        $s6 = "PathAddBackslashW"
        $s7 = "SetThreadPriority"
        $s8 = "SetFilePointerEx"
        $s9 = "GetModuleHandleW"
        $s10 = "ntoskr_nl.ex"
        $s11 = "Specif_yCach"
        $s12 = "CY-HE 4194690"
        $s13 = "RegEnumKeyExW"
        $s14 = "VerifyVersionInfoW"
        $s15 = "$REPARSE_POINT"
        $s16 = "ControlService"
        $s17 = "OpenSCManagerW"
        $s18 = "$EA_INFORMATION"
        $s19 = "GetFileAttributesW"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 119KB and
    4 of them
}
    
rule cbecbbcddfbdbceffeecfadfbf_exe {
strings:
        $s1 = "$INDEX_ALLOCATION"
        $s2 = "RegSetValueExW"
        $s3 = "SeLoadDriverPrivilege"
        $s4 = "QueryServiceStatus"
        $s5 = "DeviceIoControl"
        $s6 = "PathAddBackslashW"
        $s7 = "SetThreadPriority"
        $s8 = "SetFilePointerEx"
        $s9 = "GetModuleHandleW"
        $s10 = "ntoskr_nl.ex"
        $s11 = "Specif_yCach"
        $s12 = "CY-HE 4194690"
        $s13 = "RegEnumKeyExW"
        $s14 = "VerifyVersionInfoW"
        $s15 = "$REPARSE_POINT"
        $s16 = "ControlService"
        $s17 = "OpenSCManagerW"
        $s18 = "$EA_INFORMATION"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "OpenProcessToken"
condition:
    uint16(0) == 0x5a4d and filesize < 119KB and
    4 of them
}
    
rule cafbfbbacbfeaebddb_exe {
strings:
        $s1 = "$INDEX_ALLOCATION"
        $s2 = "RegSetValueExW"
        $s3 = "SeLoadDriverPrivilege"
        $s4 = "QueryServiceStatus"
        $s5 = "DeviceIoControl"
        $s6 = "PathAddBackslashW"
        $s7 = "SetThreadPriority"
        $s8 = "SetFilePointerEx"
        $s9 = "GetModuleHandleW"
        $s10 = "ntoskr_nl.ex"
        $s11 = "Specif_yCach"
        $s12 = "CY-HE 4194690"
        $s13 = "RegEnumKeyExW"
        $s14 = "VerifyVersionInfoW"
        $s15 = "$REPARSE_POINT"
        $s16 = "ControlService"
        $s17 = "OpenSCManagerW"
        $s18 = "$EA_INFORMATION"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "OpenProcessToken"
condition:
    uint16(0) == 0x5a4d and filesize < 119KB and
    4 of them
}
    
rule ecdfcddadeafbcecaaadbeeccfa_exe {
strings:
        $s1 = "bad function call"
        $s2 = "cross device link"
        $s3 = "english-caribbean"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "`vector destructor iterator'"
        $s6 = " exceeds the maximum of "
        $s7 = "executable format error"
        $s8 = "directory not empty"
        $s9 = "result out of range"
        $s10 = "invalid string position"
        $s11 = "operation canceled"
        $s12 = "GetConsoleOutputCP"
        $s13 = "LC_MONETARY"
        $s14 = "english-jamaica"
        $s15 = "`local vftable'"
        $s16 = "IsWindowVisible"
        $s17 = "cpp-httplib/0.9"
        $s18 = "spanish-venezuela"
        $s19 = "chinese-singapore"
        $s20 = "SetFilePointerEx"
condition:
    uint16(0) == 0x5a4d and filesize < 714KB and
    4 of them
}
    
rule dfdebfacfdbbbaeaacfefbfa_exe {
strings:
        $s1 = "StartAddressOfRawData"
        $s2 = "SizeOfInitializedData"
        $s3 = "IMAGE_DATA_DIRECTORY"
        $s4 = "RuntimeHelpers"
        $s5 = "GetMachineType"
        $s6 = "RuntimeFieldHandle"
        $s7 = "ProductName"
        $s8 = "op_Equality"
        $s9 = "VarFileInfo"
        $s10 = "ExportTable"
        $s11 = "SizeOfBlock"
        $s12 = "FileDescription"
        $s13 = "PhysicalAddress"
        $s14 = "PointerToRawData"
        $s15 = "FixedBufferAttribute"
        $s16 = "Unable to get managed delegate."
        $s17 = "SectionFinalizeData"
        $s18 = "Dll is not initialized."
        $s19 = "_isRelocated"
        $s20 = "GCHandleType"
condition:
    uint16(0) == 0x5a4d and filesize < 29KB and
    4 of them
}
    
rule ebfbbcacdffebddfaaefedcf_exe {
strings:
        $s1 = "_beginthreadex"
        $s2 = "_CorExeMain"
        $s3 = "_initialize_narrow_environment"
        $s4 = "IsWindowVisible"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleA"
        $s7 = "__std_type_info_destroy_list"
        $s8 = "__std_exception_copy"
        $s9 = "MSVCP140.dll"
        $s10 = "SetWindowPos"
        $s11 = "GetThreadContext"
        $s12 = "SuspendThread"
        $s13 = "Unknown exception"
        $s14 = "RtlCaptureContext"
        $s15 = "GetSystemTimeAsFileTime"
        $s16 = "SymInitialize"
        $s17 = "VirtualProtect"
        $s18 = "IsProcessorFeaturePresent"
        $s19 = "_execute_onexit_table"
        $s20 = "GetCurrentThread"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
rule ffbafdbeedadeecebbcfffffbfbefffba_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "VirtualAllocEx"
        $s3 = "[Caps Lock]"
        $s4 = "OThreadUnit"
        $s5 = "[Page Down]"
        $s6 = "GetKeyboardType"
        $s7 = "GetThreadLocale"
        $s8 = "HKEY_CLASSES_ROOT"
        $s9 = "SetThreadPriority"
        $s10 = "DispatchMessageA"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleA"
        $s13 = "UnhookWindowsHookEx"
        $s14 = "GetCurrentThreadId"
        $s15 = "WriteProcessMemory"
        $s16 = "GetLocalTime"
        $s17 = "TPUtilWindow"
        $s18 = "FPUMaskValue"
        $s19 = "SetEndOfFile"
        $s20 = "SetThreadContext"
condition:
    uint16(0) == 0x5a4d and filesize < 351KB and
    4 of them
}
    
rule ccdedecebaafedcdeefeec_exe {
strings:
        $s1 = "EVariantBadIndexError"
        $s2 = "DuplicateDevicePath"
        $s3 = "gEfiPcAnsiGuid"
        $s4 = "RegSetValueExA"
        $s5 = "Warning Write Failure"
        $s6 = "PoolAllocationType"
        $s7 = "LibRuntimeDebugOut"
        $s8 = "Heap32First"
        $s9 = "LoadStringA"
        $s10 = "ir;y|H9m#fF"
        $s11 = "DeviceIoControl"
        $s12 = "GetKeyboardType"
        $s13 = "GetThreadLocale"
        $s14 = "TerminateProcess"
        $s15 = "Division by zero"
        $s16 = "GetModuleHandleA"
        $s17 = "SimplePointerProtocol"
        $s18 = "GetCurrentThreadId"
        $s19 = "ConOutDevice"
        $s20 = "DrvSupEfiVer"
condition:
    uint16(0) == 0x5a4d and filesize < 155KB and
    4 of them
}
    
rule ecdeccfeeeabedefefffe_exe {
strings:
        $s1 = "get_ControlDarkDark"
        $s2 = "ConsolePokerGame.Classes"
        $s3 = "RuntimeHelpers"
        $s4 = "RuntimeFieldHandle"
        $s5 = "STAThreadAttribute"
        $s6 = "\"Exit3Ok?6"
        $s7 = "~tUvI%#\"=Q"
        $s8 = "_CorExeMain"
        $s9 = "ComputeHash"
        $s10 = "U]0Z3t=+^'<"
        $s11 = "ProductName"
        $s12 = "1:Z?Iw<d|G#"
        $s13 = "VarFileInfo"
        $s14 = "{?4 /YzCalF"
        $s15 = "get_Columns"
        $s16 = "\"AV{rtN8C,"
        $s17 = "op_Equality"
        $s18 = "FileDescription"
        $s19 = "DealTurnOrRiver"
        $s20 = "FlushFinalBlock"
condition:
    uint16(0) == 0x5a4d and filesize < 2375KB and
    4 of them
}
    
rule fccefadbbabbbbaafafdffcbaeaabdb_exe {
strings:
        $s1 = "IPInterfaceProperties"
        $s2 = "ManagementBaseObject"
        $s3 = "get_UnicastAddresses"
        $s4 = "DescriptionAttribute"
        $s5 = "RuntimeHelpers"
        $s6 = "StringComparer"
        $s7 = "GetSubKeyNames"
        $s8 = "CSharpCodeProvider"
        $s9 = "RuntimeFieldHandle"
        $s10 = "ConsoleApplication"
        $s11 = "get_ProcessorCount"
        $s12 = "STAThreadAttribute"
        $s13 = "IOException"
        $s14 = "Mix9IjP5AfN"
        $s15 = "PY:J-D[a5EU"
        $s16 = "_CorExeMain"
        $s17 = "SocketFlags"
        $s18 = "ComputeHash"
        $s19 = "get_Ordinal"
        $s20 = "PixelFormat"
condition:
    uint16(0) == 0x5a4d and filesize < 1411KB and
    4 of them
}
    
rule caabaaacbaedcdeafcfbafeeaaad_exe {
strings:
        $s1 = "IllFormedPassword"
        $s2 = "set_Impersonation"
        $s3 = "ManagementBaseObject"
        $s4 = "SuspendCountExceeded"
        $s5 = "ES_DISPLAY_REQUIRED"
        $s6 = "TxfAttributeCorrupt"
        $s7 = "dllhost.g.resources"
        $s8 = "EnterDebugMode"
        $s9 = "RuntimeHelpers"
        $s10 = "$this.GridSize"
        $s11 = "UnableToFreeVm"
        $s12 = "FlagsAttribute"
        $s13 = "FileCheckedOut"
        $s14 = "Install_Folder"
        $s15 = "set_ReceiveBufferSize"
        $s16 = "TransactionalConflict"
        $s17 = "InsufficientResources"
        $s18 = "Ot8cclCIlfL3nl3TOT"
        $s19 = "RuntimeFieldHandle"
        $s20 = "oCikTyCoNnJ1T1HUnT"
condition:
    uint16(0) == 0x5a4d and filesize < 199KB and
    4 of them
}
    
rule dadaadfbabaefbeafdcaa_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "`vector destructor iterator'"
        $s3 = "<file unknown>"
        $s4 = "Runtime Error!"
        $s5 = "CopyFileExW"
        $s6 = "jVWX$nGy7l&"
        $s7 = "`local vftable'"
        $s8 = "_Locale != NULL"
        $s9 = "gokufemologabivev"
        $s10 = "GetComputerNameA"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleW"
        $s13 = "SetSystemTimeAdjustment"
        $s14 = "SetCurrentDirectoryA"
        $s15 = "WriteProfileStringW"
        $s16 = "GetConsoleCursorInfo"
        $s17 = "GetCurrentThreadId"
        $s18 = "(((_Src))) != NULL"
        $s19 = "SetLocalTime"
        $s20 = "Expression: "
condition:
    uint16(0) == 0x5a4d and filesize < 437KB and
    4 of them
}
    
rule ddaecdfaeeabcdedfecdbcacfbcf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "Obsoleting.exe"
        $s3 = "RelativeSource"
        $s4 = "InternalPartitionEnumerator"
        $s5 = "tubiaoshangshengqushi"
        $s6 = "RuntimeFieldHandle"
        $s7 = "STAThreadAttribute"
        $s8 = "ProductName"
        $s9 = "_CorExeMain"
        $s10 = "VarFileInfo"
        $s11 = "Prestamping"
        $s12 = "FileDescription"
        $s13 = "StrokeDashArray"
        $s14 = "GetPropertyValue"
        $s15 = "435435[G32e43432t4]325[54P5r4]43554o35c435[43A54d6]443543354355d54[7r65]7e5s8[7s558]"
        $s16 = "./Fonts/#iconfont)"
        $s17 = "AncestorType"
        $s18 = "Synchronized"
        $s19 = "CornerRadius"
        $s20 = "ColumnDefinitions"
condition:
    uint16(0) == 0x5a4d and filesize < 82KB and
    4 of them
}
    
rule daddbeabcbfceebcccaaeffc_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "msctls_progress32"
        $s3 = "TMeasureItemEvent"
        $s4 = "COFREEUNUSEDLIBRARIES"
        $s5 = "UNREGISTERTYPELIBRARY"
        $s6 = "Unknown constant \"%s\""
        $s7 = "Network monitoring software from Paessler AG                "
        $s8 = "EndOffset range exceeded"
        $s9 = "Unable to insert an item"
        $s10 = "SetDefaultDllDirectories"
        $s11 = "'%s' is not a valid date"
        $s12 = "LicenseAcceptedRadio"
        $s13 = "hcessheProhinathTerm"
        $s14 = "ECompressInternalError"
        $s15 = "RemoveFontResourceA"
        $s16 = "utUserDefined:"
        $s17 = "RegSetValueExA"
        $s18 = "SetWindowTheme"
        $s19 = "ChangeResource"
        $s20 = "SetConsoleCtrlHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 2555KB and
    4 of them
}
    
rule ffadababccaeeeaeffdceabfe_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "m_RangeDecoder"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = "m_OutWindow"
        $s6 = "m_HighCoder"
        $s7 = "_CorExeMain"
        $s8 = "VarFileInfo"
        $s9 = "ProductName"
        $s10 = "FileDescription"
        $s11 = "ResolveEventArgs"
        $s12 = "GCHandleType"
        $s13 = "NumBitLevels"
        $s14 = "UpdateShortRep"
        $s15 = "m_PosStateMask"
        $s16 = "m_NumPosStates"
        $s17 = "DebuggingModes"
        $s18 = "LegalTrademarks"
        $s19 = "InitializeArray"
        $s20 = "PN)ZgmR]o#"
condition:
    uint16(0) == 0x5a4d and filesize < 35KB and
    4 of them
}
    
rule afcacbfeeccdbcdaabcadfd_exe {
strings:
        $s1 = "TooManyAlternates"
        $s2 = "_ENABLE_PROFILING"
        $s3 = "Get_StringDecrypter"
        $s4 = "ManagementBaseObject"
        $s5 = "Get_IsRemoveOn"
        $s6 = "CerArrayList`1"
        $s7 = "RuntimeFieldHandle"
        $s8 = "PrePrepareMethodAttribute"
        $s9 = "ProductName"
        $s10 = "_CorExeMain"
        $s11 = "Get_SPARENT"
        $s12 = "ComputeHash"
        $s13 = "op_Equality"
        $s14 = "VarFileInfo"
        $s15 = "oeajmIknghi"
        $s16 = "Get_PreserveEventRids"
        $s17 = "FileDescription"
        $s18 = "FlushFinalBlock"
        $s19 = "lpApplicationName"
        $s20 = "get_IsConstructor"
condition:
    uint16(0) == 0x5a4d and filesize < 417KB and
    4 of them
}
    
rule edfcacdabcbcdaffdecbdebafc_exe {
strings:
        $s1 = "CoInitializeEx"
        $s2 = "Y/~x-e@=# ,"
        $s3 = "&:S`p#g- 69"
        $s4 = "s_Z wXfeIGR"
        $s5 = "I4q-lUbV/nD"
        $s6 = ":'(T*%VfD- "
        $s7 = "zkjbf$R0.n5"
        $s8 = "Hy]ve<\".LG"
        $s9 = ",r_st-|!Yc$"
        $s10 = "~$c1T9eZ2Y`"
        $s11 = "6D8-w<^~cSy"
        $s12 = "kU5?d0^6r$/"
        $s13 = "$ @+:R=0I1X"
        $s14 = "!~?2ZT,hdMN"
        $s15 = "M*{qkc>Y&hT"
        $s16 = "GetModuleHandleA"
        $s17 = "'AZ\\#qV*8U^"
        $s18 = "//B<i w06M!["
        $s19 = "2^U2vN,'McwB"
        $s20 = "OLEAUT32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 3442KB and
    4 of them
}
    
rule abeffedabaaaaaafebfffc_exe {
strings:
        $s1 = "CreateSubItemNode"
        $s2 = "set_SelectedImageIndex"
        $s3 = "RuntimeHelpers"
        $s4 = "RuntimeFieldHandle"
        $s5 = "STAThreadAttribute"
        $s6 = "ProductName"
        $s7 = "_CorExeMain"
        $s8 = "get_Crimson"
        $s9 = "4BzqLmI*~ce"
        $s10 = "VarFileInfo"
        $s11 = "get_Company"
        $s12 = "set_ShowRootLines"
        $s13 = "GetWrappedEntity"
        $s14 = "Espresso (Large)"
        $s15 = "InitializeComponent"
        $s16 = "X0B48PBPY54U4UG747H5UX"
        $s17 = "get_FlatAppearance"
        $s18 = "Synchronized"
        $s19 = "GraphicsUnit"
        $s20 = "set_TabIndex"
condition:
    uint16(0) == 0x5a4d and filesize < 323KB and
    4 of them
}
    
rule dcdcceadafcfbcacbfadfefceceda_exe {
strings:
        $s1 = "_initialize_narrow_environment"
        $s2 = "GetConsoleWindow"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleW"
        $s5 = "GetCurrentThreadId"
        $s6 = "MSVCP140.dll"
        $s7 = "Unknown exception"
        $s8 = "GetSystemTimeAsFileTime"
        $s9 = "IsProcessorFeaturePresent"
        $s10 = "GetCurrentProcess"
        $s11 = "__current_exception_context"
        $s12 = "</assembly>"
        $s13 = "IsDebuggerPresent"
        $s14 = "_initialize_onexit_table"
        $s15 = "KERNEL32.dll"
        $s16 = "_controlfp_s"
        $s17 = ".rdata$voltmd"
        $s18 = "    <security>"
        $s19 = "bad allocation"
        $s20 = "__std_terminate"
condition:
    uint16(0) == 0x5a4d and filesize < 22KB and
    4 of them
}
    
rule aacbecfacefdffdfadafcacb_exe {
strings:
        $s1 = "RtlFreeAnsiString"
        $s2 = "[!!] Crash at addr 0x"
        $s3 = "_get_initial_narrow_environment"
        $s4 = "[-] Failed to load ntdll.dll"
        $s5 = "ExReleaseResourceLite"
        $s6 = "Intel Corporation "
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleA"
        $s13 = "__std_exception_copy"
        $s14 = "GetCurrentThreadId"
        $s15 = "NtLoadDriver"
        $s16 = "MSVCP140.dll"
        $s17 = "Durbanville1"
        $s18 = "KeBugCheckEx"
        $s19 = "FindFirstFileExW"
        $s20 = " wasn't found"
condition:
    uint16(0) == 0x5a4d and filesize < 127KB and
    4 of them
}
    
rule adcafedaccabffaeedacc_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "invalid string position"
        $s3 = "VarFileInfo"
        $s4 = "CopyFileExA"
        $s5 = "SetVolumeLabelW"
        $s6 = "`local vftable'"
        $s7 = "Sun zisosativabiv"
        $s8 = "GetThreadPriority"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleA"
        $s11 = "WriteProfileSectionW"
        $s12 = "GetConsoleCursorInfo"
        $s13 = "ContinueDebugEvent"
        $s14 = "GetCurrentThreadId"
        $s15 = "SetLocalTime"
        $s16 = "GetTickCount"
        $s17 = "Beseno tosido nevofifaf"
        $s18 = "WriteConsoleA"
        $s19 = "Unknown exception"
        $s20 = "SetHandleCount"
condition:
    uint16(0) == 0x5a4d and filesize < 147KB and
    4 of them
}
    
rule debafbddebdefefcfbcdab_exe {
strings:
        $s1 = "IoAllocateWorkItem"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "FileDescription"
        $s5 = "KdDebuggerEnabled"
        $s6 = "InitSafeBootMode"
        $s7 = "IBM Corporation "
        $s8 = "t$L;t$Hwz9\\$ ut3"
        $s9 = "KeInitializeMutex"
        $s10 = "KeGetCurrentThread"
        $s11 = "ZwQueryValueKey"
        $s12 = "nfrd965.sys"
        $s13 = "PsGetVersion"
        $s14 = "ntkrnlpa.exe"
        $s15 = "\\DosDevices\\GpdDev"
        $s16 = "OriginalFilename"
        $s17 = "ExAllocatePool"
        $s18 = "ZwOpenFile"
        $s19 = "ZwReadFile"
        $s20 = "VS_VERSION_INFO"
condition:
    uint16(0) == 0x5a4d and filesize < 29KB and
    4 of them
}
    
rule aaaffddfcfefeaabfdcebaaffc_exe {
strings:
        $s1 = ", mscor}zb, Versz"
        $s2 = "em.Collvttions.Gv"
        $s3 = "exusFile\\ftpsite.ini"
        $s4 = "Google360Browser\\Browser"
        $s5 = "ser Data\\Default\\Web"
        $s6 = "j%Xjs[j\\Zj._jpYju^jrf"
        $s7 = "Plugins\\FTP\\Hosts"
        $s8 = "RuntimeHelpers"
        $s9 = "ZwResumeThread"
        $s10 = "awrfsux.Proper"
        $s11 = "Google\\Chrommodo\\Dragon"
        $s12 = "RuntimeFieldHandle"
        $s13 = "STAThreadAttribute"
        $s14 = "iEupkzVawco"
        $s15 = "Titan Browe"
        $s16 = "_ams <NEe?T"
        $s17 = "@CEGHJNPSTW"
        $s18 = "Config Path"
        $s19 = "ProductName"
        $s20 = "_CorExeMain"
condition:
    uint16(0) == 0x5a4d and filesize < 293KB and
    4 of them
}
    
rule aefdafebccccccfeebaabda_exe {
strings:
        $s1 = "RkSwgkNb7p7E7qNONeN"
        $s2 = "$this.GridSize"
        $s3 = "STAThreadAttribute"
        $s4 = "ProductName"
        $s5 = "_CorExeMain"
        $s6 = "ComputeHash"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "IFormatProvider"
        $s10 = "set_MinimizeBox"
        $s11 = "customCultureName"
        $s12 = "SecondsRemaining"
        $s13 = "numberGroupSeparator"
        $s14 = "Synchronized"
        $s15 = "cmbEventType"
        $s16 = "UTF8Encoding"
        $s17 = "set_TabIndex"
        $s18 = "IAsyncResult"
        $s19 = "set_ShowIcon"
        $s20 = "dateTimeInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 617KB and
    4 of them
}
    
rule bddbfdaadaafafbafabbbffc_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "_CorExeMain"
        $s3 = "ProductName"
        $s4 = "FileDescription"
        $s5 = "GetFolderPath"
        $s6 = "SpecialFolder"
        $s7 = "StructLayoutAttribute"
        $s8 = "GetFullExeRunner"
        $s9 = "LayoutKind"
        $s10 = "set_UseShellExecute"
        $s11 = "IDisposable"
        $s12 = "DESCRIPTION"
        $s13 = "</assembly>"
        $s14 = "get_Location"
        $s15 = "OutBuild.exe"
        $s16 = "RunFromAdmin"
        $s17 = "WriteAllBytes"
        $s18 = "chcp 866 >NUL"
        $s19 = "    <security>"
        $s20 = "OriginalFilename"
condition:
    uint16(0) == 0x5a4d and filesize < 6713KB and
    4 of them
}
    
rule cbfffddebfcaabebacafffec_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TInterfacedPersistent"
        $s3 = "CoAddRefServerProcess"
        $s4 = "ImmSetCompositionFontA"
        $s5 = "GetEnhMetaFilePaletteEntries"
        $s6 = "Directory not empty"
        $s7 = " 2001, 2002 Mike Lischke"
        $s8 = "CoInitializeEx"
        $s9 = "OnMouseWheelUp"
        $s10 = "SetWindowTheme"
        $s11 = "ckRunningOrNew"
        $s12 = "TContextPopupEvent"
        $s13 = "WSAJoinLeaf"
        $s14 = "fsStayOnTop"
        $s15 = "Medium Gray"
        $s16 = "TOleGraphic"
        $s17 = "WSARecvFrom"
        $s18 = "TBrushStyle"
        $s19 = "LoadStringA"
        $s20 = ")IdWinSock2"
condition:
    uint16(0) == 0x5a4d and filesize < 714KB and
    4 of them
}
    
rule ceffcdfeeccfdbdadacd_exe {
strings:
        $s1 = "Yxunktfdycfjfo"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "_CorExeMain"
        $s5 = "op_Equality"
        $s6 = "VarFileInfo"
        $s7 = "Cjcwsgtohxe"
        $s8 = "FileDescription"
        $s9 = "kged^][ZWVSS"
        $s10 = "Synchronized"
        $s11 = "set_TabIndex"
        $s12 = "System.Resources"
        $s13 = "PerformLayout"
        $s14 = "MethodInvoker"
        $s15 = "    </application>"
        $s16 = "GeneratedCodeAttribute"
        $s17 = "R:0/+*(&&\"\"!"
        $s18 = "Dsfwwerjqqkpen"
        $s19 = "defaultInstance"
        $s20 = "    </security>"
condition:
    uint16(0) == 0x5a4d and filesize < 1787KB and
    4 of them
}
    
rule efdcbcdecefccabacfabdead_exe {
strings:
        $s1 = "%8lF$TDz9 7"
        $s2 = "G>_V`d<)bw'"
        $s3 = ",-mzEDSCF$^"
        $s4 = "-sNAg<\":*f"
        $s5 = "l=?1h\"{EA_"
        $s6 = "GcJPez0-Wf;"
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "PYnr\"V+1_]"
        $s10 = "!KW[^|<{RPx"
        $s11 = "aSr.OkHh^*;"
        $s12 = "f\"&g)}WAQa"
        $s13 = "7\"oHUg&<A/"
        $s14 = ":O Hjp#)D*J"
        $s15 = "wqhBC:t(<Pu"
        $s16 = "y,v:xBtf).w"
        $s17 = "FHwa) \"r@g"
        $s18 = "5F[]P}!'c<7"
        $s19 = "0lYk(#xg>Q6"
        $s20 = "T24$XCa c}z"
condition:
    uint16(0) == 0x5a4d and filesize < 9384KB and
    4 of them
}
    
rule fbcfabbccdaaccdecbacbdcfcaaaffb_exe {
strings:
        $s1 = "UnloadUserProfile"
        $s2 = "^BXg3%9.O1P"
        $s3 = "yIgv0<4?`.>"
        $s4 = "6<F2/D!mW)3"
        $s5 = "HMmQql|B>:R"
        $s6 = "}]t-U?RiZls"
        $s7 = " !r#/v,x4pM"
        $s8 = "Xd%1u#!p4v8"
        $s9 = "@;{A2LtnDVU"
        $s10 = "ueDs,\"#S4a"
        $s11 = "7}'JlLRDq*Z"
        $s12 = "M.7g9N*Bn[>"
        $s13 = "3)7}Y6|{*V&"
        $s14 = "N9_E/I;~]o-"
        $s15 = "O_J$'7]b?9s"
        $s16 = "4C<7|@2/OL!"
        $s17 = "N_h>RV{w:gq"
        $s18 = "GetModuleHandleA"
        $s19 = "*CRYPT32.dll"
        $s20 = "gMUSER32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 7001KB and
    4 of them
}
    
rule afaefdedabbfcededfddaaaae_exe {
strings:
        $s1 = "waveInGetPosition"
        $s2 = "CreateColorTransformA"
        $s3 = "CoDisconnectObject"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "mIRhl=r3aKQ"
        $s7 = "FileDescription"
        $s8 = "QueryDosDeviceA"
        $s9 = "GetShortPathNameW"
        $s10 = "TranslateBitmapBits"
        $s11 = "midiOutClose"
        $s12 = "Full Version"
        $s13 = "UnlockFileEx"
        $s14 = "6d92aDaNAr1i"
        $s15 = "SuspendThread"
        $s16 = "midiOutPrepareHeader"
        $s17 = "mciSendStringA"
        $s18 = "midiOutSetVolume"
        $s19 = "GetTempFileNameW"
        $s20 = "_abnormal_termination"
condition:
    uint16(0) == 0x5a4d and filesize < 1029KB and
    4 of them
}
    
rule baabbcddeeacbdfcdbedebadda_exe {
strings:
        $s1 = "j0T3hGHp\"J"
        $s2 = "ChromeXMp2n"
        $s3 = "Softw`He\\LM"
        $s4 = "fgaZy7V=Xo"
        $s5 = "K32JBG0<8t"
        $s6 = "8\"($@\"0/"
        $s7 = "#WaSenX A"
        $s8 = "Qu YyHV8h"
        $s9 = "y$yf})}gg."
        $s10 = "7yCkLxsT"
        $s11 = "D?lCu:7/"
        $s12 = "P>wv?dey"
        $s13 = "2345789:"
        $s14 = "HpfsEgn+"
        $s15 = "M2oHqmf/"
        $s16 = "OFw6S;be"
        $s17 = "6sA9weL["
        $s18 = "$%()*+01"
        $s19 = "2 mruCXL"
        $s20 = "B5q3k8vU"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
rule babffdeefbcefbddbdcbaaddebe_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "GetConsoleOutputCP"
        $s3 = "LoadStringW"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "GetCurrentDirectoryW"
        $s10 = "            <requestedExecutionLevel"
        $s11 = "        <requestedPrivileges>"
        $s12 = "Microsoft Corporation"
        $s13 = "GetLocalTime"
        $s14 = "UpdateWindow"
        $s15 = "'5BNTWXUNA2!"
        $s16 = "</trustInfo>"
        $s17 = "GetWindowRect"
        $s18 = "    </security>"
        $s19 = "RegOpenKeyExW"
        $s20 = "OpenProcessToken"
condition:
    uint16(0) == 0x5a4d and filesize < 375KB and
    4 of them
}
    
rule cdbbbbecbddcfedfdeccbacdfa_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "GetConsoleOutputCP"
        $s3 = "LoadStringW"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "GetCurrentDirectoryW"
        $s10 = "            <requestedExecutionLevel"
        $s11 = "        <requestedPrivileges>"
        $s12 = "Microsoft Corporation"
        $s13 = "GetLocalTime"
        $s14 = "UpdateWindow"
        $s15 = "'5BNTWXUNA2!"
        $s16 = "</trustInfo>"
        $s17 = "GetWindowRect"
        $s18 = "    </security>"
        $s19 = "RegOpenKeyExW"
        $s20 = "OpenProcessToken"
condition:
    uint16(0) == 0x5a4d and filesize < 375KB and
    4 of them
}
    
rule bffcabeefddfacecceebdd_exe {
strings:
        $s1 = "waveInGetPosition"
        $s2 = "CreateColorTransformA"
        $s3 = "CoDisconnectObject"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "QueryDosDeviceA"
        $s8 = "GetShortPathNameW"
        $s9 = "TranslateBitmapBits"
        $s10 = "midiOutClose"
        $s11 = "Full Version"
        $s12 = "UnlockFileEx"
        $s13 = ":+s6*b=]U:cP"
        $s14 = "SuspendThread"
        $s15 = "midiOutPrepareHeader"
        $s16 = "mciSendStringA"
        $s17 = "midiOutSetVolume"
        $s18 = "GetTempFileNameW"
        $s19 = "_abnormal_termination"
        $s20 = "GetFileAttributesW"
condition:
    uint16(0) == 0x5a4d and filesize < 109KB and
    4 of them
}
    
rule caeecbaccfbcbfefeffecf_exe {
strings:
        $s1 = "_Jv_RegisterClasses"
        $s2 = "0@.eh_framl"
        $s3 = "GetModuleHandleA"
        $s4 = "__deregister_frame_info"
        $s5 = "EnterCriticalSection"
        $s6 = "libgcj-16.dll"
        $s7 = "GetDriveTypeW"
        $s8 = "VirtualProtect"
        $s9 = "A:\\Windows"
        $s10 = "ExitProcess"
        $s11 = "KERNEL32.dll"
        $s12 = "VirtualQuery"
        $s13 = "$RECYCLE.BIN"
        $s14 = "FindNextFileA"
        $s15 = "ExitWindowsEx"
        $s16 = "__getmainargs"
        $s17 = "GetProcAddress"
        $s18 = "CreateProcessA"
        $s19 = "USER32.dll"
        $s20 = "msvcrt.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 29KB and
    4 of them
}
    
rule efdbddaaeffdceeeaddd_dll {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "GetModuleBaseName"
        $s3 = "ConditionalAttribute"
        $s4 = "ManagementBaseObject"
        $s5 = "RuntimeHelpers"
        $s6 = "RuntimeFieldHandle"
        $s7 = "h()I*q p\"f"
        $s8 = "#6kA/\"*XbG"
        $s9 = "ProductName"
        $s10 = "#6k@J\"&T(!"
        $s11 = "#6k@t\"+gOR"
        $s12 = "#6k?T\"+L=O"
        $s13 = "VarFileInfo"
        $s14 = "IsComObject"
        $s15 = "get_Ordinal"
        $s16 = "#6k>5\"(VE4"
        $s17 = "#6k>A\"%iRo"
        $s18 = "#6k>a\"+(%K"
        $s19 = "#6k@(\"*=PD"
        $s20 = "ThreadStaticAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 278KB and
    4 of them
}
    
rule acbffcbffbdfedbaeccffae_exe {
strings:
        $s1 = "_Jv_RegisterClasses"
        $s2 = "GetModuleHandleA"
        $s3 = "__deregister_frame_info"
        $s4 = "EnterCriticalSection"
        $s5 = "libgcj-16.dll"
        $s6 = "VirtualProtect"
        $s7 = "0@.eh_fram"
        $s8 = "ExitProcess"
        $s9 = "KERNEL32.dll"
        $s10 = "VirtualQuery"
        $s11 = "FindNextFileA"
        $s12 = "__getmainargs"
        $s13 = "GetProcAddress"
        $s14 = "msvcrt.dll"
        $s15 = "TlsGetValue"
        $s16 = "CloseHandle"
        $s17 = "LoadLibraryA"
        $s18 = "CreateFileW"
        $s19 = "GetLastError"
        $s20 = "FreeLibrary"
condition:
    uint16(0) == 0x5a4d and filesize < 32KB and
    4 of them
}
    
rule bfbaecccfbbcaeddcae_exe {
strings:
        $s1 = "_Jv_RegisterClasses"
        $s2 = "GetModuleHandleA"
        $s3 = "__deregister_frame_info"
        $s4 = "EnterCriticalSection"
        $s5 = "libgcj-16.dll"
        $s6 = "VirtualProtect"
        $s7 = "0@.eh_fram"
        $s8 = "ExitProcess"
        $s9 = "KERNEL32.dll"
        $s10 = "VirtualQuery"
        $s11 = "FindNextFileA"
        $s12 = "__getmainargs"
        $s13 = "GetProcAddress"
        $s14 = "msvcrt.dll"
        $s15 = "TlsGetValue"
        $s16 = "CloseHandle"
        $s17 = "LoadLibraryA"
        $s18 = "CreateFileW"
        $s19 = "GetLastError"
        $s20 = "FreeLibrary"
condition:
    uint16(0) == 0x5a4d and filesize < 32KB and
    4 of them
}
    