rule Ransomware_Mischa_exe {
strings:
        $s1 = "LoadAcceleratorsW"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_progress32"
        $s4 = "Can't create control."
        $s5 = "REG_RESOURCE_REQUIREMENTS_LIST"
        $s6 = "AHK_ATTACH_DEBUGGER"
        $s7 = "msctls_statusbar321"
        $s8 = "VirtualAllocEx"
        $s9 = "SetWindowTheme"
        $s10 = "RegSetValueExW"
        $s11 = "MyDocuments"
        $s12 = "ProductName"
        $s13 = "Invalid `%."
        $s14 = "Link Source"
        $s15 = "Old_Persian"
        $s16 = "u38D$xt!f9G"
        $s17 = "&Window Spy"
        $s18 = "NumpadEnter"
        $s19 = "VarFileInfo"
        $s20 = "AlwaysOnTop"
condition:
    uint16(0) == 0x5a4d and filesize < 883KB and
    4 of them
}
    
