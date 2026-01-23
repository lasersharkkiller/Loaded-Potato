
rule ELASTIC_Linux_Trojan_Gafgyt_28A2Fe0C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "28a2fe0c-eed5-4c79-81e6-3b11b73a4ebd"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L21-L38"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "04bbc6c40cdd71b4185222a822d18b96ec8427006221f213a1c9e4d9c689ce5c"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "a2c6beaec18ca876e8487c11bcc7a29279669588aacb7d3027d8d8df8f5bcead"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 2F 78 33 38 2F 78 46 4A 2F }

	condition:
		all of them
}
