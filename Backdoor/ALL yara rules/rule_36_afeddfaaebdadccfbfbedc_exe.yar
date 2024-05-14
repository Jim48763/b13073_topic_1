rule afeddfaaebdadccfbfbedc_exe {
strings:
        $s1 = "FileSystemAccessRule"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "op_Equality"
        $s5 = "_CorExeMain"
        $s6 = "dJ BQ,N6\"="
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "get_ModuleHandle"
        $s10 = "ResolveEventArgs"
        $s11 = "SecurityIdentifier"
        $s12 = "IAsyncResult"
        $s13 = "add_ResourceResolve"
        $s14 = "AgileDotNetRT"
        $s15 = "StringBuilder"
        $s16 = "CallSiteBinder"
        $s17 = "SetAccessControl"
        $s18 = "WindowsIdentity"
        $s19 = "System.Security"
        $s20 = "_Initialize64"
condition:
    uint16(0) == 0x5a4d and filesize < 261KB and
    4 of them
}
    
