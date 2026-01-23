import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_119Acead668Bad57A48B4F42F294F8F0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d3f45ee1-134f-5b16-81f8-83405a5e3181"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6847-L6858"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "bae9aed4f53059b2ec0de630f681bb157c148d9ad38be35dd8c1a74b19619077"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "11ff68da43f0931e22002f1461136c662e623366"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PB03 TRANSPORT LTD." and pe.signatures[i].serial=="11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0")
}

