
rule ELASTIC_Windows_Hacktool_Mimikatz_1Ff74F7E : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Mimikatz (Windows.Hacktool.Mimikatz)"
		author = "Elastic Security"
		id = "1ff74f7e-ec5a-45ae-b51b-2f8205445cc8"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_Mimikatz.yar#L156-L175"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1b6aad500d45de7b076942d31b7c3e77487643811a335ae5ce6783368a4a5081"
		logic_hash = "f47f760b4c373a073399c69681e76eb9dde6cfdb36c1cc31d7131376493931c0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6775be439ad1822bcaa04ed2d392143616746cfd674202aa29773c98642346f4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 74 65 48 8B 44 24 28 0F B7 80 E0 00 00 00 83 F8 10 75 54 48 8B 44 }
		$a2 = { 74 69 48 8B 44 24 28 0F B7 80 D0 00 00 00 83 F8 10 75 58 48 8B 44 }

	condition:
		all of them
}
