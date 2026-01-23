import "pe"

rule REVERSINGLABS_Cert_Blocklist_06473C3C19D9E1A9429B58B6Faec2967 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "01eba681-8c98-5553-b369-941b6dba11e2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3544-L3560"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f9ca49ce65d213dce803806956c0ce1da0c4068bea173daae9cb06dab0a86268"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Digital Leadership Solutions Limited" and pe.signatures[i].serial=="06:47:3c:3c:19:d9:e1:a9:42:9b:58:b6:fa:ec:29:67" and 1581984001<=pe.signatures[i].not_after)
}

