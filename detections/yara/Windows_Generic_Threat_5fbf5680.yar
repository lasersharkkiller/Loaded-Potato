
rule ELASTIC_Windows_Generic_Threat_5Fbf5680 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "5fbf5680-05c3-4a77-95d7-fa3cae7b4dbe"
		date = "2024-01-21"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1911-L1929"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1b0553a9873d4cda213f5464b5e98904163e347a49282db679394f70d4571e77"
		logic_hash = "ec5399f6fb29125cb4c096851b9194fa35fb1e5ddd1f4d4f07b155471ae5c619"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7cbd8d973f31505e078781bed8067ae8dce72db076c670817e1a77e48dc790fe"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 EC 3C 56 57 8B 45 08 50 E8 51 AF 00 00 83 C4 04 89 45 FC 8B 45 FC 83 C0 58 99 8B C8 8B F2 8B 45 08 99 2B C8 1B F2 89 4D F8 66 0F 57 C0 66 0F 13 45 EC C7 45 DC FF FF FF FF C7 45 E0 }

	condition:
		all of them
}
