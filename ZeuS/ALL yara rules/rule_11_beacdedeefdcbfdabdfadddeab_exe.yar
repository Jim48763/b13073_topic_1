rule beacdedeefdcbfdabdfadddeab_exe {
strings:
        $s1 = "jfjckjk9h hPo[o m+m"
        $s2 = "Bomv`js+Ememyd"
        $s3 = "ProductName"
        $s4 = "VarFileInfo"
        $s5 = "&vHNWF@\":2"
        $s6 = "FileDescription"
        $s7 = "TerminateProcess"
        $s8 = "WriteProcessMemory"
        $s9 = "\"16+)26m85:"
        $s10 = "Q+)wGVW\\E[L"
        $s11 = "\"$DCV@jDES_"
        $s12 = "RegEnumKeyExW"
        $s13 = "MakeSelfRelativeSD"
        $s14 = "\"S%$<!\"B  i4"
        $s15 = "LoadLibraryExA"
        $s16 = "SamCloseHandle"
        $s17 = "RegCreateKeyExW"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "OpenThreadToken"
        $s20 = "@g~hwyr{'<"
condition:
    uint16(0) == 0x5a4d and filesize < 6072KB and
    4 of them
}
    
