rule ebdccfaabeebbfbdde_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "RegSetValueExW"
        $s3 = "DllGetClassObject"
        $s4 = "DispatchMessageW"
        $s5 = "TerminateProcess"
        $s6 = "EnterCriticalSection"
        $s7 = "_beginthread"
        $s8 = "DigiCert1%0#"
        $s9 = "GetTickCount"
        $s10 = "browseui.dll"
        $s11 = "DllGetVersion"
        $s12 = "Anthropophagic"
        $s13 = "LoadLibraryExA"
        $s14 = "RegCreateKeyExW"
        $s15 = "Greater Manchester1"
        $s16 = "InterlockedDecrement"
        $s17 = "VirtualProtect"
        $s18 = "XYG0wt1CaW"
        $s19 = "Confusedly"
        $s20 = "GetCurrentThread"
condition:
    uint16(0) == 0x5a4d and filesize < 407KB and
    4 of them
}
    
