
rule ELASTIC_Windows_Trojan_Formbook_1112E116 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Formbook (Windows.Trojan.Formbook)"
		author = "Elastic Security"
		id = "1112e116-dee0-4818-a41f-ca5c1c41b4b8"
		date = "2021-06-14"
		modified = "2021-08-23"
		reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Formbook.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6246f3b89f0e4913abd88ae535ae3597865270f58201dc7f8ec0c87f15ff370a"
		logic_hash = "ec307a8681fa01fc0c7c0579b0e3eff10e7f373159ad58dae0a358ff16fbc10b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b8b88451ad8c66b54e21455d835a5d435e52173c86e9b813ffab09451aff7134"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 3C 30 50 4F 53 54 74 09 40 }
		$a2 = { 74 0A 4E 0F B6 08 8D 44 08 01 75 F6 8D 70 01 0F B6 00 8D 55 }
		$a3 = { 1A D2 80 E2 AF 80 C2 7E EB 2A 80 FA 2F 75 11 8A D0 80 E2 01 }
		$a4 = { 04 83 C4 0C 83 06 07 5B 5F 5E 8B E5 5D C3 8B 17 03 55 0C 6A 01 83 }

	condition:
		any of them
}
