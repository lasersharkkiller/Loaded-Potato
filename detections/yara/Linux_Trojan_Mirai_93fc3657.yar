
rule ELASTIC_Linux_Trojan_Mirai_93Fc3657 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "93fc3657-fd21-4e93-a728-c084fc0a6a4a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L259-L277"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		logic_hash = "0b5278feddd00b0b24ca735bf7cd1440379c6ce5aca6d2a6f38c9fdcedcb3c0d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d01a9e85a01fad913ca048b60bda1e5a2762f534e5308132c1d3098ac3f561ee"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 00 00 89 44 24 60 89 D1 31 C0 8B 7C 24 28 FC F3 AB 89 D1 8B 7C }

	condition:
		all of them
}
