import "pe"
import "time"

rule DITEKSHEN_INDICATOR_SUSPICIOUS_JS_WMI_Execquery
{
	meta:
		description = "Detects JS potentially executing WMI queries"
		author = "ditekSHen"
		id = "28f37b24-8bf3-5f5c-af47-dc6da5f6397a"
		date = "2024-02-22"
		modified = "2024-02-22"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_suspicious.yar#L1133-L1145"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e5145aa3a7ce54cda84929f6806a1d7b1cb37db729bb932c5c76994fb683250e"
		score = 40
		quality = 45
		tags = ""
		importance = 20

	strings:
		$ex = ".ExecQuery(" ascii nocase
		$s1 = "GetObject(" ascii nocase
		$s2 = "String.fromCharCode(" ascii nocase
		$s3 = "ActiveXObject(" ascii nocase
		$s4 = ".Sleep(" ascii nocase

	condition:
		($ex and all of ($s*))
}

