import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_627Dfdf73A1455De5143A270799E6B7B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7d5f0279-9498-5713-9c02-a025268d108f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7670-L7681"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "833e772e56e87f730ee1acb9d6ed747d239903cfd9470d777efab73c5d656f49"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7b69ff55d3c39bd7d67a10f341c1443425f0c83f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zhuhai liancheng Technology Co., Ltd." and pe.signatures[i].serial=="62:7d:fd:f7:3a:14:55:de:51:43:a2:70:79:9e:6b:7b")
}

