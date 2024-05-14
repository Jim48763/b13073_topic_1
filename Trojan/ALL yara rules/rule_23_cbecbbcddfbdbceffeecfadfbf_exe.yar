rule cbecbbcddfbdbceffeecfadfbf_exe {
strings:
        $s1 = "$INDEX_ALLOCATION"
        $s2 = "RegSetValueExW"
        $s3 = "SeLoadDriverPrivilege"
        $s4 = "QueryServiceStatus"
        $s5 = "DeviceIoControl"
        $s6 = "PathAddBackslashW"
        $s7 = "SetThreadPriority"
        $s8 = "SetFilePointerEx"
        $s9 = "GetModuleHandleW"
        $s10 = "ntoskr_nl.ex"
        $s11 = "Specif_yCach"
        $s12 = "CY-HE 4194690"
        $s13 = "RegEnumKeyExW"
        $s14 = "VerifyVersionInfoW"
        $s15 = "$REPARSE_POINT"
        $s16 = "ControlService"
        $s17 = "OpenSCManagerW"
        $s18 = "$EA_INFORMATION"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "OpenProcessToken"
condition:
    uint16(0) == 0x5a4d and filesize < 119KB and
    4 of them
}
    
