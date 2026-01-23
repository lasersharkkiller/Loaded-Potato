import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Uacbypass_CMSTPCOM : T1218 FILE
{
	meta:
		description = "Detects Windows exceutables bypassing UAC using CMSTP COM interfaces. MITRE (T1218.003)"
		author = "ditekSHen"
		id = "cdcf6e29-6ee7-5ac7-bd52-c8d42f3f8bf6"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L198-L213"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d198db97901475c0dd10603875fc339d8a7c6d40c7f9c22cda31bb0b1d6d0f2a"
		score = 40
		quality = 39
		tags = "T1218, FILE"
		importance = 20

	strings:
		$guid1 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide nocase
		$guid2 = "{3E000D72-A845-4CD9-BD83-80C07C3B881F}" ascii wide nocase
		$guid3 = "{BA126F01-2166-11D1-B1D0-00805FC1270E}" ascii wide nocase
		$s1 = "CoGetObject" fullword ascii wide
		$s2 = "Elevation:Administrator!new:" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and (1 of ($guid*) and 1 of ($s*))
}

