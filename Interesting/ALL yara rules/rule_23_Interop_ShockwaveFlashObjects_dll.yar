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
    