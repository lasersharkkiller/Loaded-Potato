import "pe"

rule REVERSINGLABS_Cert_Blocklist_47D5D5372Bcb1562B4C9F4C2Bdf13587 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Sakula malware."
		author = "ReversingLabs"
		id = "d888478e-3883-5d9d-a2b3-d59b57409b8d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2086-L2102"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fb4994647a2ed95c73625d90315c9b6deb6fb3b81b4aa6e847b0193f0a76650c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DTOPTOOLZ Co.,Ltd." and pe.signatures[i].serial=="47:d5:d5:37:2b:cb:15:62:b4:c9:f4:c2:bd:f1:35:87" and 1400803199<=pe.signatures[i].not_after)
}

