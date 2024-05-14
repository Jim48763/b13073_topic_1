rule afcfbbeffeaadcc_exe {
strings:
        $s1 = "lpszFileExtension"
        $s2 = "Yandex\\YandexBrowser"
        $s3 = "ManagementBaseObject"
        $s4 = "EnumerateDirectories"
        $s5 = "Software\\Valve\\Steam"
        $s6 = "BraveSoftware\\Brave-Browser"
        $s7 = "ValidateRemoteCertificate"
        $s8 = "RuntimeHelpers"
        $s9 = "SystemInfo.txt"
        $s10 = "GetSubKeyNames"
        $s11 = "\\Exodus\\exodus.wallet\\"
        $s12 = "GetProcessesByName"
        $s13 = "Stream cannot seek"
        $s14 = "NormalizedFilename"
        $s15 = "RuntimeFieldHandle"
        $s16 = "VolumeSerialNumber"
        $s17 = "MarshalAsAttribute"
        $s18 = "_CorExeMain"
        $s19 = "user.config"
        $s20 = "XmlNodeList"
condition:
    uint16(0) == 0x5a4d and filesize < 106KB and
    4 of them
}
    
