rule faabaffcacdbbcbeabcfddedaddba_exe {
strings:
        $s1 = "ExpandEnvironment"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "HttpAddRequestHeadersW"
        $s4 = "Failed to initialize engine state."
        $s5 = "CertGetCertificateContextProperty"
        $s6 = "RegSetValueExW"
        $s7 = "ProgramFilesFolder"
        $s8 = "QueryServiceStatus"
        $s9 = "VersionNT64"
        $s10 = "CopyFileExW"
        $s11 = "MinorUpdate"
        $s12 = "VarFileInfo"
        $s13 = "BurnPipe.%s"
        $s14 = "`local vftable'"
        $s15 = ".ExecutableName"
        $s16 = "DialogBoxParamA"
        $s17 = "FileDescription"
        $s18 = "GetThreadLocale"
        $s19 = "InternetCrackUrlW"
        $s20 = "relatedbundle.cpp"
condition:
    uint16(0) == 0x5a4d and filesize < 831KB and
    4 of them
}
    
