import "pe"

rule REVERSINGLABS_Cert_Blocklist_0C59D46580F039Af2C4Ab6Ba0Ffed197 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "969e05a1-8ae1-5ea6-9607-5bf164f34e7b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9330-L9346"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "32eea2a436f386ef44a00ef72be8be7d4070b02f84ba71c7ee1ca407fddce8ec"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\xA4\\xA7\\xE8\\xBF\\x9E\\xE7\\xBA\\xB5\\xE6\\xA2\\xA6\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="0c:59:d4:65:80:f0:39:af:2c:4a:b6:ba:0f:fe:d1:97" and 1585108595<=pe.signatures[i].not_after)
}

