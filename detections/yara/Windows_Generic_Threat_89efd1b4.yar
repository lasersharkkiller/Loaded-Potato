
rule ELASTIC_Windows_Generic_Threat_89Efd1B4 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "89efd1b4-9a4b-4749-8b34-630883d2d45b"
		date = "2024-01-11"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L954-L972"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "937c8bc3c89bb9c05b2cb859c4bf0f47020917a309bbadca36236434c8cdc8b9"
		logic_hash = "49a7875fd9c31c5c9b593aed75a28fadb586294422b75c7a8eeba2e8ff254753"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "659bdc9af01212de3d2492e0805e801b0a00630bd699360be15d3fe5b221f6b3"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 48 81 EC E0 01 00 00 48 89 9C 24 F8 01 00 00 48 83 F9 42 0F 85 03 01 00 00 48 89 84 24 F0 01 00 00 48 89 9C 24 F8 01 00 00 44 0F 11 BC 24 88 01 00 00 44 0F 11 BC 24 90 01 00 00 44 0F 11 BC 24 }

	condition:
		all of them
}
