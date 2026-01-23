
rule ELASTIC_Linux_Cryptominer_Xmrig_Af809Eea : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Xmrig (Linux.Cryptominer.Xmrig)"
		author = "Elastic Security"
		id = "af809eea-fe42-4495-b7e5-c22b39102fcd"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Xmrig.yar#L178-L196"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "00e29303b66cb39a8bc23fe91379c087376ea26baa21f6b7f7817289ba89f655"
		logic_hash = "4ae4b119a3eecfdb47a88fe5a89a4f79ae96eecf5d08eef08997357de7e6538a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "373d2f57aede0b41296011d12b59ac006f6cf0e2bd95163f518e6e252459411b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 83 E0 01 83 E1 06 09 C1 44 89 ?? 01 C9 D3 }

	condition:
		all of them
}
