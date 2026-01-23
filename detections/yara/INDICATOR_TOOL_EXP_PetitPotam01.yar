import "pe"

rule DITEKSHEN_INDICATOR_TOOL_EXP_Petitpotam01 : FILE
{
	meta:
		description = "Detect tool potentially exploiting/attempting PetitPotam"
		author = "ditekSHen"
		id = "12d7b533-f477-5fbb-8b1f-1a93c9a63500"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_tools.yar#L1127-L1143"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "37a9477b41560904e8874ecaf93eb2667b9450b5d42665677abc1442538f9000"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$s1 = "\\pipe\\lsarpc" fullword wide
		$s2 = "\\%s" fullword wide
		$s3 = "ncacn_np" fullword wide
		$s4 = /EfsRpc(OpenFileRaw|EncryptFileSrv|DecryptFileSrv|QueryUsersOnFile|QueryRecoveryAgents|RemoveUsersFromFile|AddUsersToFile)/ wide
		$r1 = "RpcBindingFromStringBindingW" fullword ascii
		$r2 = "RpcStringBindingComposeW" fullword ascii
		$r3 = "RpcStringFreeW" fullword ascii
		$r4 = "RPCRT4.dll" fullword ascii
		$r5 = "NdrClientCall2" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) and 4 of ($r*))
}

