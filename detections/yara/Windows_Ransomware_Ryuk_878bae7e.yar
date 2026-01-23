
rule ELASTIC_Windows_Ransomware_Ryuk_878Bae7E : BETA FILE MEMORY
{
	meta:
		description = "Identifies RYUK ransomware"
		author = "Elastic Security"
		id = "878bae7e-1e53-4648-93aa-b4075eef256d"
		date = "2020-04-30"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ryuk.yar#L22-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "94bed2220aeb41ae8069cee56cc5299b9fc56797d3b54085b8246a03d9e8bd93"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "93a501463bb2320a9ab824d70333da2b6f635eb5958d6f8de43fde3a21de2298"
		threat_name = "Windows.Ransomware.Ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b2 = "RyukReadMe.html" wide fullword
		$b3 = "RyukReadMe.txt" wide fullword

	condition:
		1 of ($b*)
}
