rule cfbecbeeacceabcbdadabafab_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "GetKeylogsHistory"
        $s3 = "Missing password."
        $s4 = "sLocalStateFolder"
        $s5 = "pszImplementation"
        $s6 = "LoadRemoteLibrary"
        $s7 = "IPInterfaceProperties"
        $s8 = "VerifyCrcAfterExtract"
        $s9 = "GetConnectedCamerasCount"
        $s10 = "ConditionalAttribute"
        $s11 = "get_RetrievalEntries"
        $s12 = "Directory not exists"
        $s13 = "Report sent to telegram bot"
        $s14 = "Software\\Valve\\Steam"
        $s15 = "get_BatteryLifePercent"
        $s16 = "StoreRelativeOffset"
        $s17 = "set_ContiguousWrite"
        $s18 = "_zipCrypto_forWrite"
        $s19 = "set_ForegroundColor"
        $s20 = "\\root\\SecurityCenter2"
condition:
    uint16(0) == 0x5a4d and filesize < 285KB and
    4 of them
}
    
