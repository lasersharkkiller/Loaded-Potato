
rule ELASTIC_Windows_Trojan_Cobaltstrike_663Fc95D : FILE MEMORY
{
	meta:
		description = "Identifies CobaltStrike via unidentified function code"
		author = "Elastic Security"
		id = "663fc95d-2472-4d52-ad75-c5d86cfc885f"
		date = "2021-04-01"
		modified = "2021-12-17"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L829-L847"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "842a0a372cfb2316293f4a08e1690194fa98368a9f6ffe9c63222b2c4ab6532c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d0f781d7e485a7ecfbbfd068601e72430d57ef80fc92a993033deb1ddcee5c48"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }

	condition:
		all of them
}
