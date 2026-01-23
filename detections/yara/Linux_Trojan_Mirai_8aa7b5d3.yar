
rule ELASTIC_Linux_Trojan_Mirai_8Aa7B5D3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "8aa7b5d3-e1eb-4b55-b36a-0d3a242c06e9"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1822-L1840"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
		logic_hash = "3c99b7b126184b75802c7198c81f4783af776920edc6e964dbe726d28d88f64d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "02a2c18c362df4b1fceb33f3b605586514ba9a00c7afedf71c04fa54d8146444"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 8B 4C 24 14 8B 74 24 0C 8B 5C 24 10 85 C9 74 0D 31 D2 8A 04 1A 88 }

	condition:
		all of them
}
