
rule ELASTIC_Linux_Trojan_Mirai_Fa3Ad9D0 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "fa3ad9d0-7c55-4621-90fc-6b154c44a67b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L60-L78"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		logic_hash = "5890c85872ea4508e673235b20b481972f613f6e5f9564c0237c458995532347"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fe93a3552b72b107f95cc5a7e59da64fe84d31df833bf36c81d8f31d8d79d7ca"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { CB 08 C1 CB 10 66 C1 CB 08 31 C9 8A 4F 14 D3 E8 01 D8 66 C1 }

	condition:
		all of them
}
