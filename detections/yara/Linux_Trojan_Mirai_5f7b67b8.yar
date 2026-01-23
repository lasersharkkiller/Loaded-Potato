
rule ELASTIC_Linux_Trojan_Mirai_5F7B67B8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "5f7b67b8-3d7b-48a4-8f03-b6f2c92be92e"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L832-L849"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "b2aedc0361c1093d7a996f26d907da3e4654c32a6dbcdbab441c19d4207f2e2a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6cb5fb0b7c132e9c11ac72da43278025b60810ea3733c9c6d6ca966163185940"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 38 83 CF FF 89 F8 5A 59 5F C3 57 56 83 EC 04 8B 7C 24 10 8B 4C }

	condition:
		all of them
}
