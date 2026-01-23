
rule ELASTIC_Linux_Trojan_Mirai_804F8E7C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "804f8e7c-4786-42bc-92e4-c68c24ca530e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L298-L316"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		logic_hash = "711d74406d9b0d658b3b29f647bd659699ac0af9cd482403122124ec6054f1ec"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1080d8502848d532a0b38861437485d98a41d945acaf3cb676a7a2a2f6793ac6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 31 ED 81 E1 FF 00 00 00 89 4C 24 58 89 EA C6 46 04 00 C1 FA 1F }

	condition:
		all of them
}
