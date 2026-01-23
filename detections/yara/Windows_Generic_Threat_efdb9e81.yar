
rule ELASTIC_Windows_Generic_Threat_Efdb9E81 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "efdb9e81-9004-426e-b599-331560b7f0ff"
		date = "2024-01-01"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L342-L361"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1c3302b14324c9f4e07829f41cd767ec654db18ff330933c6544c46bd19e89dd"
		logic_hash = "eae78b07f6c31e3a30ae041a27c67553bb8ea915bc7724583d78832475021955"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "ce1499c8adaad552c127ae80dad90a39eb15e1e461afe3266e8cd6961d3fde79"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 4D 61 78 69 6D 75 6D 43 68 65 63 6B 42 6F 78 53 69 7A 65 }
		$a2 = { 56 69 73 75 61 6C 50 6C 75 73 2E 4E 61 74 69 76 65 }

	condition:
		all of them
}
