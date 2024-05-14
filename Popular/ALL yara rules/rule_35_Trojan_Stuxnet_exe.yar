rule Trojan_Stuxnet_exe {
strings:
        $s1 = "it [:)7Cuos"
        $s2 = "LS|#AQ-v;KM"
        $s3 = "ZwCreateSection"
        $s4 = "GetModuleHandleW"
        $s5 = "GetCurrentThreadId"
        $s6 = "GetTickCount"
        $s7 = "Ud':aDH:*b0-"
        $s8 = "VirtualProtect"
        $s9 = "yVN6~F'?\""
        $s10 = ":hBV/?^mi."
        $s11 = "nk(&5_ sSo"
        $s12 = "d<Bmk'QVR+"
        $s13 = "<N;V@$i-UL"
        $s14 = "VKH`oPy~ql"
        $s15 = "GetCurrentProcess"
        $s16 = "A<4H#(mx(Kr"
        $s17 = "~9tgkJ\\NF0"
        $s18 = "ExitProcess"
        $s19 = "KERNEL32.dll"
        $s20 = "GetProcAddress"
condition:
    uint16(0) == 0x5a4d and filesize < 506KB and
    4 of them
}
    
