import pe
rule aadebafbcefbfffebcdaddad_exe {
strings:
        $s1 = "cross device link"
        $s2 = "english-caribbean"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "`vector destructor iterator'"
        $s5 = "executable format error"
        $s6 = "directory not empty"
        $s7 = "result out of range"
        $s8 = "invalid string position"
        $s9 = "operation canceled"
        $s10 = "LC_MONETARY"
        $s11 = "english-jamaica"
        $s12 = "`local vftable'"
        $s13 = "spanish-venezuela"
        $s14 = "chinese-singapore"
        $s15 = "Result matrix is "
        $s16 = "SetFilePointerEx"
        $s17 = "ContextStackSize"
        $s18 = "TerminateProcess"
        $s19 = "GetModuleHandleW"
        $s20 = "destination address required"
condition:
    uint16(0) == 0x5a4d and filesize < 315KB and
    4 of them
}
    
rule ccdbcbfacaaadfeabddbfaa_exe {
strings:
        $s1 = "Msctls_Progress32"
        $s2 = "WinSearchChildren"
        $s3 = "UnloadUserProfile"
        $s4 = "SetUserObjectSecurity"
        $s5 = "CreateThreadpoolTimer"
        $s6 = "`vector destructor iterator'"
        $s7 = "SetDefaultDllDirectories"
        $s8 = "AUTOITCALLVARIABLE%d"
        $s9 = "msctls_statusbar321"
        $s10 = "GUICTRLCREATECONTEXTMENU"
        $s11 = "IcmpCreateFile"
        $s12 = "Runtime Error!"
        $s13 = "<\"t|<%tx<'tt<$tp<&tl<!th<otd<]t`<[t\\<\\tX<"
        $s14 = "STARTMENUCOMMONDIR"
        $s15 = "EWM_GETCONTROLNAME"
        $s16 = "SOUNDSETWAVEVOLUME"
        $s17 = "LoadStringW"
        $s18 = "CopyFileExW"
        $s19 = "Old_Persian"
        $s20 = "$.ZVu=?QB[P"
condition:
    uint16(0) == 0x5a4d and filesize < 945KB and
    4 of them
}
    
rule aeaaaefffecbefefbddaaedabcafdbffde_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "VirtualAllocEx"
        $s3 = "RegSetValueExA"
        $s4 = "In-rmBHio%4"
        $s5 = "7Us>B-A|Fnt"
        $s6 = "GetEnhMetaFileW"
        $s7 = "GetModuleHandleA"
        $s8 = "TDen#Boc>CsT"
        $s9 = "SysListView32"
        $s10 = ".Lo0MlA7@occ-"
        $s11 = "Greater Manchester1"
        $s12 = "ImmSetOpenStatus"
        $s13 = "cr4Aof/,ke"
        $s14 = "Th:E pqYgr"
        $s15 = ":0ls&Bca.o"
        $s16 = "eaoIEv~>tA"
        $s17 = "_XcptFilter"
        $s18 = "RichEdit20A"
        $s19 = "KERNEL32.dll"
        $s20 = "ADVAPI32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 878KB and
    4 of them
}
    
rule fbffcbdecbcfdbefefdaeafce_exe {
strings:
        $s1 = "DetachFromProcess"
        $s2 = "set_bossesKilledValueLabel"
        $s3 = "GetPlayerCharacterType"
        $s4 = "updateDefeatedBossesCount"
        $s5 = "get_ButtonDraw"
        $s6 = "RuntimeHelpers"
        $s7 = " ~ 3.14159265358979323846"
        $s8 = "get_TransmitTimestamp"
        $s9 = "AuthenticationMode"
        $s10 = "get_RootDispersion"
        $s11 = "RuntimeFieldHandle"
        $s12 = "STAThreadAttribute"
        $s13 = "DesignerGeneratedAttribute"
        $s14 = "m_BugReport"
        $s15 = "TBFOVRADisp"
        $s16 = "MsgBoxStyle"
        $s17 = "get_TBFOVRA"
        $s18 = "ProductName"
        $s19 = "_CorExeMain"
        $s20 = "TBFOVHeight"
condition:
    uint16(0) == 0x5a4d and filesize < 845KB and
    4 of them
}
    