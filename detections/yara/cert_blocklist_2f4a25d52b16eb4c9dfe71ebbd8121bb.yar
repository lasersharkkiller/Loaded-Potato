import "pe"

rule REVERSINGLABS_Cert_Blocklist_2F4A25D52B16Eb4C9Dfe71Ebbd8121Bb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1afd5d2b-fd6d-58ca-b966-788d465cd0ed"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12876-L12892"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7b237ae0574afeafcc05f71512c09d3170edbee20e512a1b0af5b431923dc25c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Blist LLC" and pe.signatures[i].serial=="2f:4a:25:d5:2b:16:eb:4c:9d:fe:71:eb:bd:81:21:bb" and 1629763200<=pe.signatures[i].not_after)
}

