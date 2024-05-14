rule cbaceedbabffdadbebcfedfdebf_exe {
strings:
        $s1 = "GdipGetImageWidth"
        $s2 = "AUDIO_STREAM_STOP"
        $s3 = "GetKeyboardLayout"
        $s4 = "French - Standard"
        $s5 = "WebMonitor Client"
        $s6 = "cross device link"
        $s7 = "CreateThreadpoolTimer"
        $s8 = "`vector destructor iterator'"
        $s9 = "The service is stopped"
        $s10 = "executable format error"
        $s11 = "GetExtendedUdpTable"
        $s12 = "result out of range"
        $s13 = "send_reg_value_edit"
        $s14 = "KEYLOG_STREAM_START"
        $s15 = "directory not empty"
        $s16 = "VirtualAllocEx"
        $s17 = "RegSetValueExW"
        $s18 = "invalid string position"
        $s19 = "SetConsoleCtrlHandler"
        $s20 = "send_app_interval_set"
condition:
    uint16(0) == 0x5a4d and filesize < 773KB and
    4 of them
}
    
