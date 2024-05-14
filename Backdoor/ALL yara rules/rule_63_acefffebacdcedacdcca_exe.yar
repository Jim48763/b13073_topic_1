rule acefffebacdcedacdcca_exe {
strings:
        $s1 = "get_SamplesPerSec"
        $s2 = "_ENABLE_PROFILING"
        $s3 = "remove_ReadPacket"
        $s4 = "get_BytesTransferred"
        $s5 = "GetSystemPowerStatus"
        $s6 = "GetExtendedUdpTable"
        $s7 = "set_SelectionLength"
        $s8 = "VirtualAllocEx"
        $s9 = "GetSubKeyNames"
        $s10 = "FlagsAttribute"
        $s11 = "EnterDebugMode"
        $s12 = "mozsqlite3.dll"
        $s13 = "ForLoopInitObj"
        $s14 = "RuntimeHelpers"
        $s15 = "GetProcessesByName"
        $s16 = "STAThreadAttribute"
        $s17 = "method_1732"
        $s18 = "LastIndexOf"
        $s19 = "My.Computer"
        $s20 = "op_Equality"
condition:
    uint16(0) == 0x5a4d and filesize < 359KB and
    4 of them
}
    
