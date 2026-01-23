import "pe"

rule REVERSINGLABS_Cert_Blocklist_4C0B2E9D2Ef909D15270D4Dd7Fa5A4A5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Derusbi malware."
		author = "ReversingLabs"
		id = "97005464-1219-56d7-bd5c-f047558be1dc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2050-L2066"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9c74eb025bb413503b97ffdba6f19eadecf3789ce3a5d5419f84e32e25c9b5b1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fuqing Dawu Technology Co.,Ltd." and pe.signatures[i].serial=="4c:0b:2e:9d:2e:f9:09:d1:52:70:d4:dd:7f:a5:a4:a5" and 1372118399<=pe.signatures[i].not_after)
}

