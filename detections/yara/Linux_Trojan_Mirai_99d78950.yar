
rule ELASTIC_Linux_Trojan_Mirai_99D78950 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "99d78950-ea23-4166-a85a-7a029209f5b1"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L498-L516"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		logic_hash = "bfd628a9973f85ed0a8be2723c7ff4bd028af00ea98c9cbcde9df6aabcf394b2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3008edc4e7a099b64139a77d15ec0e2c3c1b55fc23ab156304571c4d14bc654c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 89 C3 80 BC 04 83 00 00 00 20 0F 94 C0 8D B4 24 83 00 00 00 25 FF 00 }

	condition:
		all of them
}
