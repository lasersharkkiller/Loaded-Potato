
rule ELASTIC_Windows_Generic_Threat_Bf7Aae24 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "bf7aae24-f89a-4cc6-9a15-fc29aa80af98"
		date = "2023-12-18"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L142-L160"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6dfc63894f15fc137e27516f2d2a56514c51f25b41b00583123142cf50645e4e"
		logic_hash = "b6dfa6f4c46bddd643f2f89f6275404c19fd4ed1bbae561029fffa884e99e167"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9304e9069424d43613ef9a5484214d0e3620245ef9ae64bae7d825f5f69d90c0"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 48 33 F6 44 8B EE 48 89 74 24 20 8B EE 48 89 B4 24 A8 00 00 00 44 8B F6 48 89 74 24 28 44 8B E6 E8 BF FF FF FF 4C 8B F8 8D 5E 01 B8 4D 5A 00 00 66 41 39 07 75 1B 49 63 57 3C 48 8D 4A }

	condition:
		all of them
}
