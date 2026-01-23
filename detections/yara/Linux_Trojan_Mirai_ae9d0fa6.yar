
rule ELASTIC_Linux_Trojan_Mirai_Ae9D0Fa6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "ae9d0fa6-be06-4656-9b13-8edfc0ee9e71"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1522-L1539"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8da5b14b95d96de5ced8bcab98e23973e449c1b5ca101f39a2114bb8e74fd9a5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ca2bf2771844bec95563800d19a35dd230413f8eff0bd44c8ab0b4c596f81bfc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 83 EC 04 8A 44 24 18 8B 5C 24 14 88 44 24 03 8A 44 24 10 25 FF 00 }

	condition:
		all of them
}
