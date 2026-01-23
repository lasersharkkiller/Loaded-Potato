
rule ELASTIC_Linux_Trojan_Gafgyt_5Bf62Ce4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "5bf62ce4-619b-4d46-b221-c5bf552474bb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L198-L216"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
		logic_hash = "848e0c796584cfa21afc182da5f417f5467ae84c74f52cabc13e0f5de4990232"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3ffc398303f7208e77c4fbdfb50ac896e531b7cee3be2fa820bc8d70cfb20af3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E5 56 53 31 F6 8D 45 10 83 EC 10 89 45 F4 8B 55 F4 46 8D }

	condition:
		all of them
}
