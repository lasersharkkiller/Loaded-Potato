
rule ELASTIC_Linux_Trojan_Rekoobe_7F7Aba78 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rekoobe (Linux.Trojan.Rekoobe)"
		author = "Elastic Security"
		id = "7f7aba78-6e64-41c4-a542-088a8270a941"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rekoobe.yar#L101-L119"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "50b73742726b0b7e00856e288e758412c74371ea2f0eaf75b957d73dfb396fd7"
		logic_hash = "a3b46d29fa51dd6a911cb9cb0e67e9d57d3f3b6697dc8edcc4d82f09d9819a92"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "acb8f0fb7a7b0c5329afeadb70fc46ab72a7704cdeef64e7575fbf2c2dd3dbe2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F0 89 D0 31 D8 21 F0 31 D8 03 45 F0 89 CF C1 CF 1B 01 F8 C1 }

	condition:
		all of them
}
