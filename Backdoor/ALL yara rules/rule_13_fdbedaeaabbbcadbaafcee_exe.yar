rule fdbedaeaabbbcadbaafcee_exe {
strings:
        $s1 = "^(https?|ftp):\\/\\/"
        $s2 = "        name=\"SMSvcHost\" "
        $s3 = "RuntimeHelpers"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "_CorExeMain"
        $s7 = "FileDescription"
        $s8 = "NullabilityInfo"
        $s9 = "      <assemblyIdentity "
        $s10 = "Microsoft Corporation"
        $s11 = "PrivateBuild"
        $s12 = "System.Resources"
        $s13 = "SMSvcHost.exe"
        $s14 = "Flavor=Retail"
        $s15 = "            <requestedExecutionLevel "
        $s16 = "GetResponseStream"
        $s17 = "      </compatibility> "
        $s18 = "UnexpectedValue"
        $s19 = "ExceptionUtilities"
        $s20 = "get_StartInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 44KB and
    4 of them
}
    
