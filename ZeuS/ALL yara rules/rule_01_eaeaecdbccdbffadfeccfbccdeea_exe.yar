rule eaeaecdbccdbffadfeccfbccdeea_exe {
strings:
        $s1 = "GetSystemPowerStatus"
        $s2 = "CertOpenSystemStoreW"
        $s3 = "CryptReleaseContext"
        $s4 = "CoInitializeEx"
        $s5 = "GetUserNameExW"
        $s6 = "VolumeSerialNumber"
        $s7 = "9*929:9@9G9M9S9[96:O=n=7>>>t>"
        $s8 = "Xv`gseGkoiZ"
        $s9 = "ub%+X*&Y/,("
        $s10 = "Company: %s"
        $s11 = "id74.#&1>)+"
        $s12 = ":(1;ex|)Vn,"
        $s13 = "hvnc_module"
        $s14 = "WSAGetLastError"
        $s15 = "Process32FirstW"
        $s16 = "text/javascript"
        $s17 = "HttpEndRequestA"
        $s18 = "Accept-Encoding"
        $s19 = "*/wp-login.php*"
        $s20 = "Win32_DiskDrive"
condition:
    uint16(0) == 0x5a4d and filesize < 285KB and
    4 of them
}
    
