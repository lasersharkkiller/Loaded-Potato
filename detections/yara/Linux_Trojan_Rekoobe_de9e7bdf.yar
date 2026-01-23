
rule ELASTIC_Linux_Trojan_Rekoobe_De9E7Bdf : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rekoobe (Linux.Trojan.Rekoobe)"
		author = "Elastic Security"
		id = "de9e7bdf-c515-4af8-957a-e489b7cb9716"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rekoobe.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "447da7bee72c98c2202f1919561543e54ec1b9b67bd67e639b9fb6e42172d951"
		logic_hash = "bdc4a3e4eeffc0d32e6a86dda54beceab8301d0065731d9ade390392ab4c6126"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ab3f0b9179a136f7c1df43234ba3635284663dee89f4e48d9dfc762fb762f0db"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F5 48 89 D6 48 C1 EE 18 40 0F B6 F6 48 33 2C F1 48 89 D6 48 C1 }

	condition:
		all of them
}
