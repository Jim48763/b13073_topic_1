rule efedaeaacafdbdfbcebfcd_exe {
strings:
        $s1 = "Too many open sockets"
        $s2 = "    -S              Do not show confidence estimators and warnings."
        $s3 = "    -z attributes   String to insert as td or th attributes"
        $s4 = "Directory not empty"
        $s5 = "The specified thread is detached"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LOG: header received:"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "Connection reset by peer"
        $s12 = "Non-2xx responses:      %d"
        $s13 = "TerminateProcess"
        $s14 = "Content-type: %s"
        $s15 = "InitializeCriticalSection"
        $s16 = "Too many processes"
        $s17 = "Address already in use"
        $s18 = " !\"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s19 = "Total:      %5I64d %5I64d%5I64d"
        $s20 = "    -n requests     Number of requests to perform"
condition:
    uint16(0) == 0x5a4d and filesize < 77KB and
    4 of them
}
    
