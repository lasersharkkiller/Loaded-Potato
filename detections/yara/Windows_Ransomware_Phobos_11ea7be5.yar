
rule ELASTIC_Windows_Ransomware_Phobos_11Ea7Be5 : BETA FILE MEMORY
{
	meta:
		description = "Identifies Phobos ransomware"
		author = "Elastic Security"
		id = "11ea7be5-7aac-41d7-8d09-45131a9c656e"
		date = "2020-06-25"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phobos"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Phobos.yar#L45-L64"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "1f86695f316200c92d0d02f5f3ba9f68854978f98db5d4291a81c06c9f0b8d28"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "a264f93e085134e5114c5d72e1bf93e70935e33756a79f1021e9c1e71d6c8697"
		threat_name = "Windows.Ransomware.Phobos"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b1 = { C0 74 30 33 C0 40 8B CE D3 E0 85 C7 74 19 66 8B 04 73 66 89 }

	condition:
		1 of ($b*)
}
