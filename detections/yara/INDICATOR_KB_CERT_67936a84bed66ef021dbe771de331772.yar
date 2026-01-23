import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_67936A84Bed66Ef021Dbe771De331772 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2739308a-7396-5fe2-bf1b-fe7e6e5d1f80"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7876-L7889"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "da149e6835be937e0bf2763052d4cbabb367910061aec3c394dffaa45d9b0ac6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8fff75906628b764e99a7a028112a8ec7794097e564f0f897c24c2baaa82ded8"
		reason = "IcedID"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APEX SOFTWARE DESIGN, LLC" and pe.signatures[i].serial=="67:93:6a:84:be:d6:6e:f0:21:db:e7:71:de:33:17:72")
}

