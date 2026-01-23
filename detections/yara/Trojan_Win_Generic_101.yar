
rule FIREEYE_RT_Trojan_Win_Generic_101 : FILE
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "0290aaea-d65b-5883-97f9-549d107e3e1f"
		date = "2020-11-25"
		date = "2020-11-25"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/BEACON/supplemental/yara/Trojan_Win_Generic_101.yar#L4-L20"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "2e67c62bd0307c04af469ee8dcb220f2"
		logic_hash = "e530183f3cab01560b1abc91e2111e5d9e5aadc1c8134027ac07d8917f9419a0"
		score = 75
		quality = 75
		tags = "FILE"
		rev = 3

	strings:
		$s0 = { 2A [1-16] 17 [1-16] 02 04 00 00 [1-16] FF 15 }
		$s1 = { 81 7? [1-3] 02 04 00 00 7? [1-3] 83 7? [1-3] 17 7? [1-3] 83 7? [1-3] 2A 7? }
		$s2 = { FF 15 [4-16] FF D? [1-16] 3D [1-24] 89 [1-8] E8 [4-16] 89 [1-8] F3 A4 [1-24] E8 }
		$si1 = "PeekMessageA" fullword
		$si2 = "PostThreadMessageA" fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and @s0[1]<@s1[1] and @s1[1]<@s2[1] and all of them
}
