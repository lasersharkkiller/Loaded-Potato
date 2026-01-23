
rule ELASTIC_Windows_Trojan_Netwire_F42Cb379 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Netwire (Windows.Trojan.Netwire)"
		author = "Elastic Security"
		id = "f42cb379-ac8c-4790-a6d3-aad6dc4acef6"
		date = "2022-08-14"
		modified = "2022-09-29"
		reference = "https://www.elastic.co/security-labs/netwire-dynamic-configuration-extraction"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Netwire.yar#L66-L90"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ab037c87d8072c63dc22b22ff9cfcd9b4837c1fee2f7391d594776a6ac8f6776"
		logic_hash = "fc1436596987d3971a464e707ee6fd5689e7d2800df471c125c1e3f748537f5d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a52d2be082d57d07ab9bb9087dd258c29ef0528c4207ac6b31832f975a1395b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "http://%s%ComSpec" ascii fullword
		$a2 = "%c%.8x%s" ascii fullword
		$a3 = "%6\\6Z65dlNh\\YlS.dfd" ascii fullword
		$a4 = "GET %s HTTP/1.1" ascii fullword
		$a5 = "R-W65: %6:%S" ascii fullword
		$a6 = "PTLLjPq %6:%S -qq9/G.y" ascii fullword

	condition:
		4 of them
}
