rule DcRat_RAT_Windows : RAT NET {
  meta:
    author      = "@_lubiedo"
    date        = "26-05-2022"
    description = "DcRat by qwqdanchun"
    hash0       = "4530c2681887c0748cc2ecddb1976d15ad813a4a01e5810fd8b843adcd2fd3d0"
    ref0        = "https://github.com/qwqdanchun/DcRat"
  strings:
    $magic  = { 4D 5A }
    $s01    = "/c schtasks /create /f /sc onlogon /rl highest /tn " base64wide
    $s02    = "Select * from Win32_CacheMemory" wide fullword
    $s03    = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" base64wide
    $s04    = "timeout 3 > NUL" wide fullword
    $s05    = "Pac_ket" wide fullword
    $s06    = "Po_ng" wide fullword
    $s07    = "plu_gin" wide fullword
    $s08    = "AmsiScanBuffer" base64wide
    $s09    = "MsMpEng.exe" wide fullword
  condition:
    filesize < 1MB and $magic and all of ($s*)
}


