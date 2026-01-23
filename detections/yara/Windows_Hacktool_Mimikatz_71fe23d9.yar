
rule ELASTIC_Windows_Hacktool_Mimikatz_71Fe23D9 : FILE
{
	meta:
		description = "Subject: Benjamin Delpy"
		author = "Elastic Security"
		id = "71fe23d9-ee1a-47fb-a99f-2be2eb9ccb1a"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Mimikatz.yar#L114-L133"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "856687718b208341e7caeea2d96da10f880f9b5a75736796a1158d4c8755f678"
		logic_hash = "6d1e84bb8532c6271ad3966055eac8d60ec019d8ae6632efb59463c35b46ad9b"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "22b1f36e82e604fc3a80bb5abf87aef59957b1ceeb050eea3c9e85fb0b937db1"
		threat_name = "Windows.Hacktool.Mimikatz"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $subject_name
}
