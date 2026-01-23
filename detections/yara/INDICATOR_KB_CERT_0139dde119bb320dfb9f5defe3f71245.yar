import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0139Dde119Bb320Dfb9F5Defe3F71245 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4962ea0c-ce99-57d3-8848-48dcaab4f346"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8071-L8084"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b2a7154d73eb9271a181d71d65c73e399bb2f7d1fe031240e94b6ef4c4f7cb18"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "23d13a8e48a6eff191a5d6a0635b99467c2e7242ae520479cae130fbd41cc645"
		reason = "RedLineStealer"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hangil IT Co., Ltd" and pe.signatures[i].serial=="01:39:dd:e1:19:bb:32:0d:fb:9f:5d:ef:e3:f7:12:45")
}

