import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Dcratby : FILE
{
	meta:
		description = "Detects executables containing the string DcRatBy"
		author = "ditekSHen"
		id = "d8408cc0-0245-59b7-9134-1f4edd811df7"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1502-L1510"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1a0f863fb71c84a9a01c3f07da0fdff9ea06b061f85532ac523d6a5d1e0e1e11"
		score = 40
		quality = 45
		tags = "FILE"
		importance = 20

	strings:
		$s1 = "DcRatBy" ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}

