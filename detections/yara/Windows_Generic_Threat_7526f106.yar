
rule ELASTIC_Windows_Generic_Threat_7526F106 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "7526f106-018f-41b9-a1bf-15f7d9f2188e"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1586-L1605"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5a297c446c27a8d851c444b6b32a346a7f9f5b5e783564742d39e90cd583e0f0"
		logic_hash = "a0f9eb760be05196f0c5c3e3bf250929b48341a58a11c24722978fa19c4a9f57"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "5f5fc4152aae94b9c3bc0380dbcb093289c840a29b629b1d76a09c672daa9586"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 50 72 6F 6A 65 63 74 31 2E 75 45 78 57 61 74 63 68 }
		$a2 = { 6C 49 45 4F 62 6A 65 63 74 5F 44 6F 63 75 6D 65 6E 74 43 6F 6D 70 6C 65 74 65 }

	condition:
		all of them
}
