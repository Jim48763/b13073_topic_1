rule cdeecdbfadbfacedfcfadd_exe {
strings:
        $s1 = "UpdateInstallMode"
        $s2 = "AI_INST_PRODCODES"
        $s3 = "bad function call"
        $s4 = "Common Start Menu"
        $s5 = "Enterprise Admins"
        $s6 = "cross device link"
        $s7 = "WarningMessageBox"
        $s8 = "RunAllExitActions"
        $s9 = "AI_SKIP_MSI_ELEVATION"
        $s10 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s11 = "Remote Management Users"
        $s12 = "SetLatestVersionPath"
        $s13 = "Various custom actions"
        $s14 = "executable format error"
        $s15 = "DOMAIN_NT_AUTHORITY"
        $s16 = "result out of range"
        $s17 = "directory not empty"
        $s18 = "Terminal Server License Servers"
        $s19 = "AiSkipUserExit"
        $s20 = "invalid string position"
condition:
    uint16(0) == 0x5a4d and filesize < 1283KB and
    4 of them
}
    
