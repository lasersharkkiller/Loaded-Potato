import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0C48732873Ac8Ccebaf8F0E1E8329Cec : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "dacde33d-3925-52c6-87fd-9f3ead6bfab0"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8686-L8699"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "64c61d1bb48d790a2a3da85c6e57b542f0ee8a85296fc3e8c17ea18d8241790d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "14ffc96c8cc2ea2d732ed75c3093d20187a4c72d02654ff4520448ba7f8c7df6"
		reason = "HermeticWiper"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hermetica Digital Ltd" and pe.signatures[i].serial=="0c:48:73:28:73:ac:8c:ce:ba:f8:f0:e1:e8:32:9c:ec")
}

