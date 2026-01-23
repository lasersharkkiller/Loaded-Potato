
rule ELASTIC_Windows_Generic_Threat_Ce98C4Bc : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "ce98c4bc-22bb-4c2b-bced-8fc36bd3a2f0"
		date = "2023-12-17"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L21-L40"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "950e8a29f516ef3cf1a81501e97fbbbedb289ad9fb93352edb563f749378da35"
		logic_hash = "74914f41c03cb2dcb1dc3175cc76574a0d40b66a1a3854af8f50c9858704b66b"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "d0849208c71c1845a6319052474549dba8514ecf7efe6185c1af22ad151bdce7"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 4D 65 73 73 61 67 65 50 61 63 6B 4C 69 62 2E 4D 65 73 73 61 67 65 50 61 63 6B }
		$a2 = { 43 6C 69 65 6E 74 2E 41 6C 67 6F 72 69 74 68 6D }

	condition:
		all of them
}
