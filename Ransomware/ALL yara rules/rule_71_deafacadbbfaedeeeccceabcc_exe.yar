rule deafacadbbfaedeeeccceabcc_exe {
strings:
        $s1 = "ReadFile failed, err = %d"
        $s2 = "\\all users\\microsoft\\"
        $s3 = "CryptReleaseContext"
        $s4 = "id-kp-timeStamping"
        $s5 = "?456789:;<="
        $s6 = "id-at-dnQualifier"
        $s7 = "GetComputerNameW"
        $s8 = "InitializeCriticalSection"
        $s9 = "id-at-postalAddress"
        $s10 = "GetCurrentThreadId"
        $s11 = "GetLocalTime"
        $s12 = "GetTickCount"
        $s13 = "SetEndOfFile"
        $s14 = "Microsoft Hv"
        $s15 = "RSA with MD5"
        $s16 = "id-at-surName"
        $s17 = "AttachConsole"
        $s18 = "rsaEncryption"
        $s19 = "MapViewOfFile"
        $s20 = "Time Stamping"
condition:
    uint16(0) == 0x5a4d and filesize < 266KB and
    4 of them
}
    
