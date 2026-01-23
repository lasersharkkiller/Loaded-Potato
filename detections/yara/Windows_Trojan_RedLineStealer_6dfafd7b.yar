
rule ELASTIC_Windows_Trojan_Redlinestealer_6Dfafd7B : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Redlinestealer (Windows.Trojan.RedLineStealer)"
		author = "Elastic Security"
		id = "6dfafd7b-5188-4ec7-9ba4-58b8f05458e5"
		date = "2024-01-05"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_RedLineStealer.yar#L168-L186"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "809e303ba26b894f006b8f2d3983ff697aef13b67c36957d98c56aae9afd8852"
		logic_hash = "888bc2fdfae8673cd6bce56fc9894b3cab6d7e3c384d854d6bc8aef47fdecf1c"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "b7770492fc26ada1e5cb5581221f59b1426332e57eb5e04922f65c25b92ad860"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 33 38 46 34 33 31 41 35 34 39 34 31 31 41 45 42 33 32 38 31 30 30 36 38 41 34 43 38 33 32 35 30 42 32 44 33 31 45 31 35 }

	condition:
		all of them
}
