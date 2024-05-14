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
    
