import pe
rule dbbfacabcdaefeffaefaa_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "GetWindowDC"
        $s3 = "[bwGS1M'}4 "
        $s4 = "Me)L$*1|]mG"
        $s5 = "24MC,.Km(+I"
        $s6 = "_CorExeMain"
        $s7 = "VarFileInfo"
        $s8 = "13M*,.KQ)+I"
        $s9 = "ProductName"
        $s10 = "13P&+-Mq(*K"
        $s11 = "_initialize_narrow_environment"
        $s12 = "FileDescription"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleW"
        $s15 = "m reconhecimento autom"
        $s16 = " automaticamente o ambiente mais compat"
        $s17 = "InitializeComponent"
        $s18 = "AssemblyTitleAttribute"
        $s19 = "GetCurrentThreadId"
        $s20 = "0eaJ0&C\"PL`"
condition:
    uint16(0) == 0x5a4d and filesize < 653KB and
    4 of them
}
    
rule dffdfcfcafcffafadfbdbbbffebaeeba_exe {
strings:
        $s1 = "dwCreationDisposition"
        $s2 = "EnterDebugMode"
        $s3 = "GetWindowDC"
        $s4 = "_CorExeMain"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "CreateCompatibleBitmap"
        $s8 = "i destroyed your mbr"
        $s9 = "DialogResult"
        $s10 = "GdiAlphaBlend"
        $s11 = "    </application>"
        $s12 = "i want to be loved"
        $s13 = "InvalidateRect"
        $s14 = "MessageBoxIcon"
        $s15 = "piLargeVersion"
        $s16 = "set_FormatFlags"
        $s17 = "FileFlagDeleteOnClose"
        $s18 = "BLENDFUNCTION"
        $s19 = "blendFunction"
        $s20 = "DebuggingModes"
condition:
    uint16(0) == 0x5a4d and filesize < 203KB and
    4 of them
}
    
rule cbbeaaddebebfcaafefbddf_exe {
strings:
        $s1 = "PQ7R5STUVWX"
        $s2 = "_initialize_narrow_environment"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleW"
        $s5 = "@winRainbow2! rainbow"
        $s6 = "GetCurrentThreadId"
        $s7 = "CreateCompatibleDC"
        $s8 = "GetTickCount"
        $s9 = "[\\]^]_`abcd-"
        $s10 = "NtRaiseHardError"
        $s11 = "GetSystemTimeAsFileTime"
        $s12 = "IsProcessorFeaturePresent"
        $s13 = "GetCurrentProcess"
        $s14 = "__current_exception_context"
        $s15 = "GetSystemMetrics"
        $s16 = "</assembly>"
        $s17 = "IsDebuggerPresent"
        $s18 = "_initialize_onexit_table"
        $s19 = "RedrawWindow"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 178KB and
    4 of them
}
    
rule dbdebecfdaadcbaefbf_exe {
strings:
        $s1 = "set_TransparencyKey"
        $s2 = "EnterDebugMode"
        $s3 = "GetProcessesByName"
        $s4 = "BreakOnTermination"
        $s5 = "STAThreadAttribute"
        $s6 = "pictureBox8"
        $s7 = "sound_file2"
        $s8 = "op_Equality"
        $s9 = "HT|x%=~M}ZO"
        $s10 = "Anti-Po0p3r"
        $s11 = "_CorExeMain"
        $s12 = "VarFileInfo"
        $s13 = "ProductName"
        $s14 = "set_WindowState"
        $s15 = "set_MinimizeBox"
        $s16 = "FileDescription"
        $s17 = "Clutt.Properties"
        $s18 = "InitializeComponent"
        $s19 = "AssemblyTitleAttribute"
        $s20 = "next_payload"
condition:
    uint16(0) == 0x5a4d and filesize < 1853KB and
    4 of them
}
    
rule fbfeeaadfddfdeabdceeabfaf_exe {
strings:
        $s1 = "FontColor_Tick"
        $s2 = "RuntimeHelpers"
        $s3 = "AuthenticationMode"
        $s4 = "STAThreadAttribute"
        $s5 = "DesignerGeneratedAttribute"
        $s6 = "ProductName"
        $s7 = "m_inScopeNs"
        $s8 = "op_Equality"
        $s9 = "MsgBoxStyle"
        $s10 = "_CorExeMain"
        $s11 = "VarFileInfo"
        $s12 = "ThreadStaticAttribute"
        $s13 = "ProcessXElement"
        $s14 = "set_MinimizeBox"
        $s15 = "FileDescription"
        $s16 = "  Microsoft 2010"
        $s17 = "AutoSaveSettings"
        $s18 = "DebuggerHiddenAttribute"
        $s19 = "InitializeComponent"
        $s20 = "CancelEventHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 429KB and
    4 of them
}
    
rule fdcacaeecbcffeeeae_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "13P&+-Mq(*K"
        $s4 = "24MC,.Km(+I"
        $s5 = "_CorExeMain"
        $s6 = "Me)L$*1|]mG"
        $s7 = "VarFileInfo"
        $s8 = "13M*,.KQ)+I"
        $s9 = "FileDescription"
        $s10 = "m reconhecimento autom"
        $s11 = " automaticamente o ambiente mais compat"
        $s12 = "InitializeComponent"
        $s13 = "0eaJ0&C\"PL`"
        $s14 = "B~VqDkG$JzPV"
        $s15 = "Synchronized"
        $s16 = "    </application>"
        $s17 = "GeneratedCodeAttribute"
        $s18 = "clr-namespace:eye"
        $s19 = "eye.MainWindow"
        $s20 = "eye.Properties.Resources"
condition:
    uint16(0) == 0x5a4d and filesize < 779KB and
    4 of them
}
    
rule aecdcbdecccbefdcdeccbcaeaec_exe {
strings:
        $s1 = "RegSetValueExA"
        $s2 = "GetWindowDC"
        $s3 = "_initialize_narrow_environment"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "GetCurrentThreadId"
        $s7 = "CreateCompatibleDC"
        $s8 = "nopqrstsCPAD"
        $s9 = "_`abcdefg8fh"
        $s10 = "GetTickCount"
        $s11 = "NtRaiseHardError"
        $s12 = "RegCreateKeyExA"
        $s13 = "GetSystemTimeAsFileTime"
        $s14 = "U.3[*1;\"M"
        $s15 = "'()*+,-./0"
        $s16 = "IsProcessorFeaturePresent"
        $s17 = "GetCurrentProcess"
        $s18 = "__current_exception_context"
        $s19 = "GetSystemMetrics"
        $s20 = "</assembly>"
condition:
    uint16(0) == 0x5a4d and filesize < 111KB and
    4 of them
}
    
rule bebcfbeebdfbcbeeeaeedac_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "_CorExeMain"
        $s4 = "VarFileInfo"
        $s5 = "FileDescription"
        $s6 = "n para la compatibilidad"
        $s7 = "Form1_FormClosing"
        $s8 = "shutdown -r -t 00"
        $s9 = "InitializeComponent"
        $s10 = "set_TabIndex"
        $s11 = "GraphicsUnit"
        $s12 = "DialogResult"
        $s13 = "Synchronized"
        $s14 = "System.Resources"
        $s15 = "PerformLayout"
        $s16 = "    </application>"
        $s17 = "GeneratedCodeAttribute"
        $s18 = "set_InitialImage"
        $s19 = "defaultInstance"
        $s20 = "add_FormClosed"
condition:
    uint16(0) == 0x5a4d and filesize < 42KB and
    4 of them
}
    
rule deeafabfbacbbcdbbbeecfcc_exe {
strings:
        $s1 = "GetWindowDC"
        $s2 = "PQ7R5STUVWX"
        $s3 = "_initialize_narrow_environment"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "GetCurrentThreadId"
        $s7 = "CreateCompatibleDC"
        $s8 = "GetTickCount"
        $s9 = "[\\]^]_`abcd-"
        $s10 = "SystemQuestion"
        $s11 = "NtRaiseHardError"
        $s12 = "GetSystemTimeAsFileTime"
        $s13 = "PlaySoundA"
        $s14 = "IsProcessorFeaturePresent"
        $s15 = "GetCurrentProcess"
        $s16 = "__current_exception_context"
        $s17 = "GetSystemMetrics"
        $s18 = "RSDS$7]-T3I"
        $s19 = "</assembly>"
        $s20 = "IsDebuggerPresent"
condition:
    uint16(0) == 0x5a4d and filesize < 179KB and
    4 of them
}
    
rule aaefdacdcdbcaacabfcced_exe {
strings:
        $s1 = "White Office Logo"
        $s2 = "QpTAU^T_SwS}TTV3Y"
        $s3 = "TU PC FUE INFECTADA!!"
        $s4 = "24GM`fnqjkd`d^d^``fk{"
        $s5 = "11ABOOZY__``____`___ZZQQFF;;00\"\""
        $s6 = "{{oooovv|{xxhhPP<<55<<EEDD33"
        $s7 = "||utiiZZII:9..((''(())(($$"
        $s8 = "**56??FFJIIIEE==23''"
        $s9 = ",+66=>@A@@<<55..'' "
        $s10 = "$41904400-BE18-11D3-A28B-00104BD35090"
        $s11 = "  ''00;;DDJKMMMMJIDD==55++"
        $s12 = "65BAAAFGJKCD*+"
        $s13 = "*)54<<AAAB;;21,,&&"
        $s14 = "WordScreamerWindow"
        $s15 = "STAThreadAttribute"
        $s16 = "Q(8(c1M1?***4\"!\""
        $s17 = "&&66DDOOVW\\\\aaggoowx"
        $s18 = "Q9W4X0n+SEa"
        $s19 = "A%8=;U2w*W&"
        $s20 = "O|D?H%K!QC["
condition:
    uint16(0) == 0x5a4d and filesize < 8313KB and
    4 of them
}
    
rule aadddcbaeeecbbbdbdfbad_exe {
strings:
        $s1 = "]jWzwzHvHv[~[~laL"
        $s2 = "ResolveTypeHandle"
        $s3 = "FileSystemAccessRule"
        $s4 = "FlagsAttribute"
        $s5 = "EnterDebugMode"
        $s6 = "FileSystemSecurity"
        $s7 = "STAThreadAttribute"
        $s8 = "qUZg\"9m7iv"
        $s9 = "crazysound7"
        $s10 = "wJ{k`YxATC:"
        $s11 = "kr9jZvD4p$G"
        $s12 = "% 7~K{[k#h/"
        $s13 = "SoundPlayer"
        $s14 = "m`_a[yAqQ~p"
        $s15 = "e*w:rV]vj^F"
        $s16 = "dp.Qq\"4=Y&"
        $s17 = "3[h'W$%|Q=*"
        $s18 = "\"f!KxqitbQ"
        $s19 = "UX_T*fil:zc"
        $s20 = "Ud}m7<o^5T]"
condition:
    uint16(0) == 0x5a4d and filesize < 8287KB and
    4 of them
}
    
rule bdadbcfabdbacbfabecabcacbbaa_exe {
strings:
        $s1 = "[ #(@Ib:oz-"
        $s2 = "ZW<Vng62N #"
        $s3 = "*xuIKL-po 3"
        $s4 = "l(T%0{CMgHV"
        $s5 = "VarFileInfo"
        $s6 = "ProductName"
        $s7 = "FileDescription"
        $s8 = "pUef>ISU~{nT"
        $s9 = "VirtualProtect"
        $s10 = "@qJiY9yS0{"
        $s11 = "K5JT;=BYz]"
        $s12 = ";UC>]jv?#t"
        $s13 = "$BFH hYw:."
        $s14 = "ExitProcess"
        $s15 = "SHLWAPI.dll"
        $s16 = "YQL@bSQX\\}{"
        $s17 = "COMCTL32.dll"
        $s18 = "GetProcAddress"
        $s19 = "ShellExecuteExA"
        $s20 = "CoInitialize"
condition:
    uint16(0) == 0x5a4d and filesize < 557KB and
    4 of them
}
    
rule eecffedefddddacdfefaeeefefbaee_exe {
strings:
        $s1 = "CreateNamespaceAttribute"
        $s2 = "fn/;6uEh\"5\\D"
        $s3 = "RuntimeHelpers"
        $s4 = "AuthenticationMode"
        $s5 = "STAThreadAttribute"
        $s6 = "DesignerGeneratedAttribute"
        $s7 = "ComputeHash"
        $s8 = "System.Linq"
        $s9 = "tm\"#~e 1%N"
        $s10 = "MsgBoxStyle"
        $s11 = "ORL2&Y-v|lB"
        $s12 = "n!a<&6kIC-U"
        $s13 = "b*gFzHXMGTO"
        $s14 = "og<T%rkL?2l"
        $s15 = "ej.^1$m|=+b"
        $s16 = "op_Equality"
        $s17 = "VarFileInfo"
        $s18 = "1_Us*5i&aq2"
        $s19 = "LyO-ZId@#]4"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 4801KB and
    4 of them
}
    
rule fbeeaecccedaefaecfccbafc_exe {
strings:
        $s1 = "_initialize_narrow_environment"
        $s2 = "GetModuleHandleW"
        $s3 = "TerminateProcess"
        $s4 = "CreateCompatibleDC"
        $s5 = "GetCurrentThreadId"
        $s6 = "GetTickCount"
        $s7 = "NtRaiseHardError"
        $s8 = "GetSystemTimeAsFileTime"
        $s9 = "IsProcessorFeaturePresent"
        $s10 = "GetCurrentProcess"
        $s11 = "GetSystemMetrics"
        $s12 = "</assembly>"
        $s13 = "IsDebuggerPresent"
        $s14 = "_initialize_onexit_table"
        $s15 = "_controlfp_s"
        $s16 = "RedrawWindow"
        $s17 = "KERNEL32.dll"
        $s18 = "    <security>"
        $s19 = "VirtualAlloc"
        $s20 = "USER32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 18KB and
    4 of them
}
    
rule acafbfdadceabeddfbdadbd_exe {
strings:
        $s1 = "dwKVj)^a*\""
        $s2 = "&XpisyGlA\""
        $s3 = "9;7fJ0joOFn"
        $s4 = "+6QYFja.'uv"
        $s5 = "b9skNa8@K*2"
        $s6 = "/jEMl;xz9vm"
        $s7 = "a9edw&q^|P8"
        $s8 = "+PH>32'\"g%"
        $s9 = "QZBSxL]oVc_"
        $s10 = "{e\".@9[,4+"
        $s11 = "\"~Ng_Zn#Wh"
        $s12 = "{b\"ilqgvc&"
        $s13 = "R8}^p8e7Q[sq"
        $s14 = "zutk*nn60{MH"
        $s15 = ":`[/^KBUc\\'"
        $s16 = "3,\"/\"^U$G4j"
        $s17 = "VirtualProtect"
        $s18 = "T`3u1)Dl@="
        $s19 = "~-s/!nDY v"
        $s20 = "+8LT{E!9b="
condition:
    uint16(0) == 0x5a4d and filesize < 2074KB and
    4 of them
}
    
rule aaadeafdaaaafcebeeffcbcdba_exe {
strings:
        $s1 = "WinSearchChildren"
        $s2 = "msctls_progress32"
        $s3 = "SetUserObjectSecurity"
        $s4 = "SetDefaultDllDirectories"
        $s5 = "AUTOITCALLVARIABLE%d"
        $s6 = "msctls_statusbar321"
        $s7 = "GUICTRLCREATECONTEXTMENU"
        $s8 = "Runtime Error!"
        $s9 = "IcmpCreateFile"
        $s10 = "<\"t|<%tx<'tt<$tp<&tl<!th<otd<]t`<[t\\<\\tX<"
        $s11 = "EWM_GETCONTROLNAME"
        $s12 = "STARTMENUCOMMONDIR"
        $s13 = "SOUNDSETWAVEVOLUME"
        $s14 = "OpenWindowStationW"
        $s15 = "CopyFileExW"
        $s16 = "LoadStringW"
        $s17 = "~f;D$@ulIyt"
        $s18 = "</security>"
        $s19 = "Run Script:"
        $s20 = "Old_Persian"
condition:
    uint16(0) == 0x5a4d and filesize < 1003KB and
    4 of them
}
    
rule adbefdffcaccfededbaefbbcdbbbccae_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "AuthenticationMode"
        $s3 = "STAThreadAttribute"
        $s4 = "DesignerGeneratedAttribute"
        $s5 = "ProductName"
        $s6 = "_CorExeMain"
        $s7 = "VarFileInfo"
        $s8 = "ThreadStaticAttribute"
        $s9 = "set_MinimizeBox"
        $s10 = "FileDescription"
        $s11 = "set_AutoSizeMode"
        $s12 = "AutoSaveSettings"
        $s13 = "DebuggerHiddenAttribute"
        $s14 = "InitializeComponent"
        $s15 = "CancelEventHandler"
        $s16 = "System.Media"
        $s17 = "set_TabIndex"
        $s18 = "GraphicsUnit"
        $s19 = "Synchronized"
        $s20 = "set_IsSingleInstance"
condition:
    uint16(0) == 0x5a4d and filesize < 131KB and
    4 of them
}
    
rule AxInterop_ShockwaveFlashObjects_dll {
strings:
        $s1 = "VarFileInfo"
        $s2 = "FileDescription"
        $s3 = "remove_FlashCall"
        $s4 = "remove_FSCommand"
        $s5 = "IAsyncResult"
        $s6 = "eventMulticaster"
        $s7 = "get_FlashVars"
        $s8 = "TCurrentLabel"
        $s9 = "add_OnProgress"
        $s10 = "SeamlessTabbing"
        $s11 = "set_ScaleMode"
        $s12 = "AttachInterfaces"
        $s13 = "ClsidAttribute"
        $s14 = "get_DeviceFont"
        $s15 = "DetachSink"
        $s16 = "MulticastDelegate"
        $s17 = "RaiseOnFlashCall"
        $s18 = "_CorDllMain"
        $s19 = "get_Profile"
        $s20 = "get_Quality"
condition:
    uint16(0) == 0x5a4d and filesize < 22KB and
    4 of them
}
    
rule bfefbacffdbdccfdbbbeeddc_exe {
strings:
        $s1 = "_get_initial_narrow_environment"
        $s2 = "RegSetValueExA"
        $s3 = "GetModuleHandleW"
        $s4 = "TerminateProcess"
        $s5 = "GetCurrentThreadId"
        $s6 = "RegCreateKeyExA"
        $s7 = "GetSystemTimeAsFileTime"
        $s8 = "IsProcessorFeaturePresent"
        $s9 = "GetCurrentProcess"
        $s10 = "</assembly>"
        $s11 = "IsDebuggerPresent"
        $s12 = "_initialize_onexit_table"
        $s13 = "_controlfp_s"
        $s14 = "ADVAPI32.dll"
        $s15 = "KERNEL32.dll"
        $s16 = "    <security>"
        $s17 = "USER32.dll"
        $s18 = "3\"3#4,474>4^4d4j4p4v4|4"
        $s19 = "CloseHandle"
        $s20 = "MessageBoxA"
condition:
    uint16(0) == 0x5a4d and filesize < 18KB and
    4 of them
}
    
rule ddfdccedadbaacafecdfd_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "TerminateProcess"
        $s3 = "GetModuleHandleA"
        $s4 = "GetTextExtentPoint32A"
        $s5 = "GetLocalTime"
        $s6 = "Es hora de formatear"
        $s7 = "IsBadWritePtr"
        $s8 = "WNetOpenEnumA"
        $s9 = "OpenSCManagerA"
        $s10 = "ControlService"
        $s11 = "SetHandleCount"
        $s12 = "GetCurrentProcess"
        $s13 = "GetSystemMetrics"
        $s14 = "ExitProcess"
        $s15 = "HeapDestroy"
        $s16 = "IsBadReadPtr"
        $s17 = "KERNEL32.dll"
        $s18 = "FlushFileBuffers"
        $s19 = "GetProcAddress"
        $s20 = "VirtualAlloc"
condition:
    uint16(0) == 0x5a4d and filesize < 55KB and
    4 of them
}
    
rule dfacdfeeecedafcddfaabc_exe {
strings:
        $s1 = "k^lmnopqr===st"
        $s2 = "=>7?@ABCD77EFG"
        $s3 = "_initialize_narrow_environment"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "GetCurrentThreadId"
        $s7 = "CreateCompatibleDC"
        $s8 = "GetTickCount"
        $s9 = "NOPQRSTTUVJW"
        $s10 = "bajkKKlmdaQG'"
        $s11 = "NtRaiseHardError"
        $s12 = "GetSystemTimeAsFileTime"
        $s13 = "i*bf6!W9't"
        $s14 = "IsProcessorFeaturePresent"
        $s15 = "GetCurrentProcess"
        $s16 = "__current_exception_context"
        $s17 = "GetSystemMetrics"
        $s18 = "</assembly>"
        $s19 = "IsDebuggerPresent"
        $s20 = "_initialize_onexit_table"
condition:
    uint16(0) == 0x5a4d and filesize < 86KB and
    4 of them
}
    
rule eaeabdccddadbefccbcdcfbeb_exe {
strings:
        $s1 = "invalid distance code"
        $s2 = "lk}\"Wg[JVa"
        $s3 = "Mq$eJwS:o^%"
        $s4 = "cT[yM$-S/,u"
        $s5 = "r}91O`j|'4!"
        $s6 = "ebf@~h8\"FP"
        $s7 = "A$-3j'L#x+U"
        $s8 = "U&/3Lus,.=*"
        $s9 = "(pkqx!C[jG3"
        $s10 = "}lszPC^DIcg"
        $s11 = "F(y0k\"}ztC"
        $s12 = "VarFileInfo"
        $s13 = "ProductName"
        $s14 = "ZbG(i'A]S\""
        $s15 = "CkYVh?DE]cj"
        $s16 = "\"@8pHnUCPR"
        $s17 = ">!JV~m:/\"Y"
        $s18 = "jC@`<_MDT|8"
        $s19 = "IsWindowVisible"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 4614KB and
    4 of them
}
    
rule Interop_ShockwaveFlashObjects_dll {
strings:
        $s1 = "SecurityRulesAttribute"
        $s2 = "FlashObject"
        $s3 = "ProductName"
        $s4 = "VarFileInfo"
        $s5 = "IDispatchEx"
        $s6 = "FileDescription"
        $s7 = "DispIdAttribute"
        $s8 = "remove_FlashCall"
        $s9 = "CoClassAttribute"
        $s10 = "remove_FSCommand"
        $s11 = "RemoteQueryService"
        $s12 = "get_FlashVars"
        $s13 = "IFlashFactory"
        $s14 = "TCurrentLabel"
        $s15 = "add_OnProgress"
        $s16 = "System.Security"
        $s17 = "SeamlessTabbing"
        $s18 = "GetNameSpaceParent"
        $s19 = "set_ScaleMode"
        $s20 = "get_DeviceFont"
condition:
    uint16(0) == 0x5a4d and filesize < 26KB and
    4 of them
}
    