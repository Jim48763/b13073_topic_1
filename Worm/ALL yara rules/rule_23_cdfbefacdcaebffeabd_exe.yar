rule cdfbefacdcaebffeabd_exe {
strings:
        $s1 = "GetTouchInputInfo"
        $s2 = "cross device link"
        $s3 = "msctls_progress32"
        $s4 = "ivitada.  Kas soovite kohe taask"
        $s5 = "Hungarian=Ez az alkalmaz"
        $s6 = "SetDefaultDllDirectories"
        $s7 = "Desea reiniciarlo ahora?"
        $s8 = "Spanish=La instalaci"
        $s9 = "lreiz palaidiet uzst"
        $s10 = "o do build de %s falhou. "
        $s11 = "Swedish=%s av %s har h"
        $s12 = " versiune de %s nu este suportat"
        $s13 = "executable format error"
        $s14 = "tirmesi indiriliyor; bu i"
        $s15 = "cia nie je k dispoz"
        $s16 = "directory not empty"
        $s17 = "de, kas var ilgt da"
        $s18 = "chargement.  Erreur"
        $s19 = "re installasjonen p"
        $s20 = "result out of range"
condition:
    uint16(0) == 0x5a4d and filesize < 6817KB and
    4 of them
}
    
