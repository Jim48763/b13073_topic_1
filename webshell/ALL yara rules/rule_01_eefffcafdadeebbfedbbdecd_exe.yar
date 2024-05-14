rule eefffcafdadeebbfedbbdecd_exe {
strings:
        $s1 = "Dispose__Instance__   "
        $s2 = "D i s a b l e C M D  yH K E Y _ C U R R E N T _ U S E R \\ S o f t w a r e \\ P o l i c i e s \\ M i c r o s o f t \\ W i n d o w s \\ S y s t e m  "
        $s3 = "H K E Y _ C U R R E N T _ U S E R \\ S o f t w a r e \\ M i c r o s o f t \\ W i n d o w s \\ C u r r e n t V e r s i o n \\ P o l i c i e s \\ S y s t e m  )D i s a b l e R e g i s t r y T o o l s  "
        $s4 = "H K E Y _ L O C A L _ M A C H I N E \\ S O F T W A R E \\ M i c r o s o f t \\ W i n d o w s   N T \\ C u r r e n t V e r s i o n \\ S y s t e m R e s t o r e  "
        $s5 = "5 5 5 2  A5 c 0 5 f 9 6 9 f 6 b 0 a 0 a c d a 3 0 8 f 0 b e 4 b c 8 b 1 f  [S o f t w a r e \\ M i c r o s o f t \\ W i n d o w s \\ C u r r e n t V e r s i o n \\ R u n  "
        $s6 = "    </security>"
        $s7 = "</assembly>"
        $s8 = "/ p a s s . e x e  mh t t p s : / / d l . d r o p b o x . c o m / s / p 8 4 a a z 2 8 t 0 h e p u l / P a s s . e x e ? d l = 0  "
        $s9 = "Create__Instance__"
        $s10 = "MyTemplate"
        $s11 = ",  SS o f t w a r e \\ M i c r o s o f t \\ I n t e r n e t   E x p l o r e r \\ M a i n  "
        $s12 = "                _CorExeMain mscoree.dll     "
        $s13 = "p i n g s t o p  1t a s k k i l l   / F   / I M   P I N G . E X E  "
        $s14 = "E n a b l e R e s t o r e  %D i s a b l e T a s k M a n a g e r  "
        $s15 = "S o f t w a r e  3c m d . e x e   / k   p i n g   0   &   d e l   \"  "
        $s16 = "Mn e t s h   f i r e w a l l   d e l e t e   a l l o w e d p r o g r a m   \"  "
        $s17 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING "
        $s18 = "r e s t a r t c o m p u t e r  #s h u t d o w n   - r   - t   0 0 "
        $s19 = "s e n d m u s i c p l a y  "
        $s20 = "0  D i s a b l e R e g i s t r y  "
condition:
    uint16(0) == 0x5a4d and filesize < 45KB and
    4 of them
}
    
