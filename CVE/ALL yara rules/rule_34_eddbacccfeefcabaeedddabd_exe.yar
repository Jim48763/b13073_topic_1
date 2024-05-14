rule eddbacccfeefcabaeedddabd_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1569KB and
    4 of them
}
    
