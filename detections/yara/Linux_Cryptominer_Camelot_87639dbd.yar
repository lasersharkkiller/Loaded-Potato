
rule ELASTIC_Linux_Cryptominer_Camelot_87639Dbd : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "87639dbd-da2d-4cf9-a058-16f4620a5a7f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L238-L256"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d2d8421ffdcebb7fed00edcf306ec5e86fc30ad3e87d55e85b05bea5dc1f7d63"
		logic_hash = "b81af8c9baee999b91e63f97d5a46451d9960487b25b04079df5539f857be466"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c145df0a671691ef2bf17644ec7c33ebb5826d330ffa35120d4ba9e0cb486282"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 00 48 83 C2 01 48 89 EF 48 89 53 38 FF 50 18 48 8D 7C 24 30 48 }

	condition:
		all of them
}
