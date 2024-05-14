rule Ransomware_WannaCryptr_v_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "            processorArchitecture=\"*\""
        $s3 = "CryptReleaseContext"
        $s4 = "invalid distance code"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "FileDescription"
        $s8 = "GetModuleHandleA"
        $s9 = "GetCurrentDirectoryA"
        $s10 = "InitializeCriticalSection"
        $s11 = "Microsoft Corporation"
        $s12 = "OLEAUT32.dll"
        $s13 = "invalid window size"
        $s14 = "k?44@K!H>!dL1"
        $s15 = "_local_unwind2"
        $s16 = "    </security>"
        $s17 = "need dictionary"
        $s18 = "        <assemblyIdentity"
        $s19 = "incorrect header check"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 229KB and
    4 of them
}
    
