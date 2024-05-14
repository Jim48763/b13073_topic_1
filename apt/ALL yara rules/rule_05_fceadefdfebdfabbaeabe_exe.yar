rule fceadefdfebdfabbaeabe_exe {
strings:
        $s1 = "id-ce-extKeyUsage"
        $s2 = "`vector destructor iterator'"
        $s3 = "Certificate Policies"
        $s4 = "id-kp-timeStamping"
        $s5 = "?456789:;<="
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "`local vftable'"
        $s10 = "id-at-dnQualifier"
        $s11 = "TerminateProcess"
        $s12 = "SetFilePointerEx"
        $s13 = "BLINDING CONTEXT"
        $s14 = "EnterCriticalSection"
        $s15 = "SetCurrentDirectoryW"
        $s16 = "id-at-uniqueIdentifier"
        $s17 = "Microsoft Corporation"
        $s18 = "BLOWFISH-ECB"
        $s19 = "RSA with MD5"
        $s20 = "Unique Identifier"
condition:
    uint16(0) == 0x5a4d and filesize < 392KB and
    4 of them
}
    