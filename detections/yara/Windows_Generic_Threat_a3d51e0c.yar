
rule ELASTIC_Windows_Generic_Threat_A3D51E0C : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "a3d51e0c-9d49-48e5-abdb-ceeb10780cfa"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1382-L1400"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "18bd25df1025cd04b0642e507b0170bc1a2afba71b2dc4bd5e83cc487860db0d"
		logic_hash = "f128f6a037abb4af2c11605b182852146780be6451b3062a2914bedb5c286843"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "069a218c752b5aac5b26b19b36b641b3dd31f09d7fcaae735efb52082a3495cc"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 55 8B EC 53 56 8B 75 08 33 DB 39 5D 14 57 75 10 3B F3 75 10 39 5D 0C 75 12 33 C0 5F 5E 5B 5D C3 3B F3 74 07 8B 7D 0C 3B FB 77 1B E8 05 F8 FF FF 6A 16 5E 89 30 53 53 53 53 53 E8 97 F7 FF FF 83 }

	condition:
		all of them
}
