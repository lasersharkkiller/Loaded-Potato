
rule ELASTIC_Linux_Trojan_Winnti_4C5A1865 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Winnti (Linux.Trojan.Winnti)"
		author = "Elastic Security"
		id = "4c5a1865-ff41-445b-8616-c83b87498c2b"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "0d963a713093fc8e5928141f5747640c9b43f3aadc8a5478c949f7ec364b28ad"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Winnti.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "69f6dcba59ec8cd7f4dfe853495a35601e35d74476fad9e18bef7685a68ece51"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "685fe603e04ff123b3472293d3d83e2dc833effd1a7e6c616ff17ed61df0004c"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C1 E8 1F 84 C0 75 7B 85 D2 89 D5 7E 75 8B 47 0C 39 C6 7D 6E 44 8D }

	condition:
		all of them
}
