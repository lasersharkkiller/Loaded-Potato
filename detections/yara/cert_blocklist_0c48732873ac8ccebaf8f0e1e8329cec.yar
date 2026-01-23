import "pe"

rule REVERSINGLABS_Cert_Blocklist_0C48732873Ac8Ccebaf8F0E1E8329Cec : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b531341a-e8ac-5b56-a202-3c072f5d2ce0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10238-L10254"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7c9476a4119e013c8bb3c14b607090d592feaa5f2fc0f78d810555681d4a3733"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hermetica Digital Ltd" and pe.signatures[i].serial=="0c:48:73:28:73:ac:8c:ce:ba:f8:f0:e1:e8:32:9c:ec" and 1618272000<=pe.signatures[i].not_after)
}

