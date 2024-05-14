rule dacbaeacaecbeeddcfcedaca_dll {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "cross device link"
        $s3 = "SetDefaultDllDirectories"
        $s4 = "executable format error"
        $s5 = "result out of range"
        $s6 = "directory not empty"
        $s7 = "<file unknown>"
        $s8 = "invalid string position"
        $s9 = "ninvalid null pointer"
        $s10 = "operation canceled"
        $s11 = "ProductName"
        $s12 = "VarFileInfo"
        $s13 = "`local vftable'"
        $s14 = "FileDescription"
        $s15 = "RemoveDirectoryA"
        $s16 = "TerminateProcess"
        $s17 = "SetFilePointerEx"
        $s18 = "SetThreadStackGuarantee"
        $s19 = "destination address required"
        $s20 = "ClusterGetEnumCount"
condition:
    uint16(0) == 0x5a4d and filesize < 639KB and
    4 of them
}
    