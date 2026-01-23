import "pe"

rule REVERSINGLABS_Cert_Blocklist_0C14B611A44A1Bae0E8C7581651845B6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "116beeac-49c6-56b0-a1c0-855623f604d9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5464-L5480"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7f6028181e33e4ba8264ee367169e7259e19ff49dcae9a337a4ba78c06b459e6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NEEDCODE SP Z O O" and pe.signatures[i].serial=="0c:14:b6:11:a4:4a:1b:ae:0e:8c:75:81:65:18:45:b6" and 1600300801<=pe.signatures[i].not_after)
}

