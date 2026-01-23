
rule ELASTIC_Linux_Cryptominer_Camelot_83550472 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "83550472-4c97-4afc-b187-1a7ffc9acbbc"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L178-L196"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d2d8421ffdcebb7fed00edcf306ec5e86fc30ad3e87d55e85b05bea5dc1f7d63"
		logic_hash = "f62d4a2a7dfb312b2e362844bfa29bd4453a05f31b4f72550ef29ff40ed6fb9d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "63cf1cf09ad06364e1b1f15774400e0544dbb0f38051fc795b4fc58bd08262d1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FA 48 8D 4A 01 48 D1 E9 48 01 CA 48 29 F8 48 01 C3 49 89 C4 48 }

	condition:
		all of them
}
