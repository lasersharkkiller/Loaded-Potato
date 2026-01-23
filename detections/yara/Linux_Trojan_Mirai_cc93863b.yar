
rule ELASTIC_Linux_Trojan_Mirai_Cc93863B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "cc93863b-1050-40ba-9d02-5ec9ce6a3a28"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1802-L1820"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
		logic_hash = "881998dee010270d7cefae5b59a888e541d4a2b93e3e52ae0abe0df41371c50d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f3ecd30f0b511a8e92cfa642409d559e7612c3f57a1659ca46c77aca809a00ac"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C3 57 8B 44 24 0C 8B 4C 24 10 8B 7C 24 08 F3 AA 8B 44 24 08 }

	condition:
		all of them
}
