rule ebdcffebabefeacdffcfcdca_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "AudioEndpointType"
        $s3 = "EventLogEntryType"
        $s4 = "Requested Key Log"
        $s5 = "StaticPerformance"
        $s6 = "set_MonikerString"
        $s7 = "_notEncodedBuffer"
        $s8 = "_keyboardDelegate"
        $s9 = "DESKTOP_ENUMERATE"
        $s10 = "HSHELL_APPCOMMAND"
        $s11 = "set_FillWithZeros"
        $s12 = "GetFrameMoveRects"
        $s13 = "CommandDictionary"
        $s14 = "remove_SendFailed"
        $s15 = "First display is 1."
        $s16 = "AdministrationApiVersion"
        $s17 = "ClientCommandsCommunication"
        $s18 = "TCP_TABLE_BASIC_CONNECTIONS"
        $s19 = "ConditionalAttribute"
        $s20 = "QDC_DATABASE_CURRENT"
condition:
    uint16(0) == 0x5a4d and filesize < 1022KB and
    4 of them
}
    
