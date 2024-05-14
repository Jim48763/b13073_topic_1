rule bafcadbeccedff_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "System.Linq"
        $s3 = "_CorExeMain"
        $s4 = "ComputeHash"
        $s5 = "+6hv.-z7`sO"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "PixelOffsetMode"
        $s10 = "ImageAttributes"
        $s11 = "CompositingMode"
        $s12 = "ResolveEventArgs"
        $s13 = "DebuggerHiddenAttribute"
        $s14 = "Eqsqvvmso.d.resources"
        $s15 = "Synchronized"
        $s16 = "GraphicsUnit"
        $s17 = "get_CurrentThread"
        $s18 = "System.Resources"
        $s19 = "AutoScaleMode"
        $s20 = "get_ManagedThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 598KB and
    4 of them
}
    
