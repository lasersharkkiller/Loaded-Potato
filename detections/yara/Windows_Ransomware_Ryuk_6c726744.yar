
rule ELASTIC_Windows_Ransomware_Ryuk_6C726744 : BETA FILE MEMORY
{
	meta:
		description = "Identifies RYUK ransomware"
		author = "Elastic Security"
		id = "6c726744-acdb-443a-b683-b11f8b657f7a"
		date = "2020-04-30"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ryuk"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ryuk.yar#L44-L67"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "ee7586d5cbef23d1863a4dfcc5da9b97397c993268881922c681022bf4f293f0"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "d0a4608907e48d02d78ff40a59d47cad1b9258df31b7312dd1a85f8fee2a28d5"
		threat_name = "Windows.Ransomware.Ryuk"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "172.16." ascii fullword
		$a2 = "192.168." ascii fullword
		$a3 = "DEL /F" wide fullword
		$a4 = "lsaas.exe" wide fullword
		$a5 = "delete[]" ascii fullword

	condition:
		4 of ($a*)
}
