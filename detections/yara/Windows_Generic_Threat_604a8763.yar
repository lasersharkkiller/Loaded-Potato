
rule ELASTIC_Windows_Generic_Threat_604A8763 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "604a8763-7ec1-4474-b238-2ebbaf24afa2"
		date = "2024-03-05"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L3144-L3162"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2a51fb11032ec011448184a4f2837d05638a7673d16dcf5dcf4005de3f87883a"
		logic_hash = "cf88c0d102680fc7c16d49b6e8dc49c16b27d5940edf078e667a45e70ebe3883"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c74c1dc7588d01112c3995b17e9772af15fb1634ebfb417b8c0069ac1f334e74"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 51 8B 45 0C 48 89 45 FC EB 07 8B 45 FC 48 89 45 FC 83 7D FC 00 7C 0B 8B 45 08 03 45 FC C6 00 00 EB E8 C9 C3 55 8B EC 83 EC 0C 8B 45 0C 89 45 FC 8B 45 08 3B 45 10 76 2F 8B 45 FC 89 45 }

	condition:
		all of them
}
