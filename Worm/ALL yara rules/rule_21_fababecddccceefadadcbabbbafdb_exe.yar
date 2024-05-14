rule fababecddccceefadadcbabbbafdb_exe {
strings:
        $s1 = "bad function call"
        $s2 = "msctls_progress32"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "CreateThreadpoolTimer"
        $s6 = "`vector destructor iterator'"
        $s7 = "disconnect_native_host"
        $s8 = "executable format error"
        $s9 = "directory not empty"
        $s10 = "CryptReleaseContext"
        $s11 = "result out of range"
        $s12 = "   </security>"
        $s13 = "Runtime Error!"
        $s14 = "Failed to create a random name"
        $s15 = "invalid string position"
        $s16 = "operation canceled"
        $s17 = "GetConsoleOutputCP"
        $s18 = ".?AVbad_cast@std@@"
        $s19 = "LoadStringW"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 924KB and
    4 of them
}
    
