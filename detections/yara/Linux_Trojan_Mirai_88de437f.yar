
rule ELASTIC_Linux_Trojan_Mirai_88De437F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "88de437f-9c98-4e1d-96c0-7b433c99886a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1363-L1381"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		logic_hash = "233dbf3d13c35f4c9c7078d67ea60086355c801ce6515f9d3c518e95afd39d85"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c19eb595c2b444a809bef8500c20342c9f46694d3018e268833f9b884133a1ea"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 08 8B 4C 24 04 85 D2 74 0D 31 C0 89 F6 C6 04 08 00 40 39 D0 }

	condition:
		all of them
}
