rule aababcecabbdebceaeabddacdadb_exe {
strings:
        $s1 = "Invalid filename."
        $s2 = "GetEnvironmentStrings"
        $s3 = "RegSetValueExA"
        $s4 = "CoRegisterMessageFilter"
        $s5 = "ProductName"
        $s6 = "LoadStringA"
        $s7 = "VarFileInfo"
        $s8 = "Link Source"
        $s9 = "FileDescription"
        $s10 = "GetThreadLocale"
        $s11 = ".?AVCClientDC@@"
        $s12 = "IsWindowVisible"
        $s13 = "TerminateProcess"
        $s14 = "UnregisterClassA"
        $s15 = "DispatchMessageA"
        $s16 = "GetModuleHandleA"
        $s17 = "EnterCriticalSection"
        $s18 = "Magnification Factor"
        $s19 = "z{}|wx{|uvy|uvx|uvx|tux|pqsd"
        $s20 = "mnqdrsv|stv|tux|uvy|vwy|yz||"
condition:
    uint16(0) == 0x5a4d and filesize < 441KB and
    4 of them
}
    
