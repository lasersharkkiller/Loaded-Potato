
rule VOLEXITY_Apt_Win_Powerstar_Memonly : CHARMINGKITTEN
{
	meta:
		description = "Detects the initial stage of the memory only variant of PowerStar."
		author = "threatintel@volexity.com"
		id = "469fc433-da9e-55ed-99fb-9560ec86a179"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L20-L65"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "d790ff204e4e8adeb3e887d9ebce743e958b523c48317d017487b1b0c6aebc11"
		score = 75
		quality = 78
		tags = "CHARMINGKITTEN"
		hash1 = "977cf5cc1d0c61b7364edcf397e5c67d910fac628c6c9a41cf9c73b3720ce67f"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s_1 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($in.substring(3)))"
		$s_2 = "[Convert]::ToByte(([Convert]::ToString(-bnot ($text_bytes[$i])"
		$s_3 = "$Exec=[System.Text.Encoding]::UTF8.GetString($text_bytes)"
		$s_4 = "((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})"
		$f_1 = "function Gorjol{"
		$f_2 = "Borjol \"$"
		$f_3 = "Gorjol -text"
		$f_4 = "function Borjoly{"
		$f_6 = "$filename = $env:APPDATA+\"\\Microsoft\\Windows\\DocumentPreview.pdf\";"
		$f_7 = "$env:APPDATA+\"\\Microsoft\\Windows\\npv.txt\""
		$f_8 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\brt8ts74e.bat"
		$f_9 = "\\Microsoft\\Windows\\s7qe52.txt"
		$f_10 = "$yeolsoe2 = $yeolsoe"
		$f_11 = "setRequestHeader(\"Content-DPR\""
		$f_12 = "getResponseHeader(\"Content-DPR\")"
		$f_13 = {24 43 6f 6d 6d 61 6e 64 50 61 72 74 73 20 3d 24 53 65 73 73 69 6f 6e 52 65 73 70 6f 6e 73 65 2e 53 70 6c 69 74 28 22 b6 22 29}
		$f_14 = "$language -like \"*shar*\""
		$f_15 = "$language -like \"*owers*\""
		$alias_1 = "(gcm *v????E?P?e*)"
		$alias_2 = "&(gcm *ke-e*) $Command"
		$key = "T2r0y1M1e1n1o0w1"
		$args_1 = "$sem.Close()"
		$args_2 = "$cem.Close()"
		$args_3 = "$mem.Close()"
		$command_1 = "_____numone_____"
		$command_2 = "_____mac2_____"
		$command_3 = "_____yeolsoe_____"

	condition:
		2 of ($s_*) or any of ($f_*) or 2 of ($alias_*) or $key or all of ($args_*) or any of ($command_*)
}
