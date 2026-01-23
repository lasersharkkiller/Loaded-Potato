
rule ELASTIC_Linux_Trojan_Mirai_A68E498C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "a68e498c-0768-4321-ab65-42dd6ef85323"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1343-L1361"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		logic_hash = "e4552813dc92b397c5ba78f32ee6507520f337b55779a3fc705de7e961f8eb8f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "951c9dfcba531e5112c872395f6c144c4bc8b71c666d2c7d9d8574a23c163883"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 39 D0 7E 25 8B 4C 24 38 01 D1 8A 11 8D 42 9F 3C 19 77 05 8D }

	condition:
		all of them
}
