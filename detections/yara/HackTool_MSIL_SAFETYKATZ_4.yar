
rule FIREEYE_RT_Hacktool_MSIL_SAFETYKATZ_4 : FILE
{
	meta:
		description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SafetyKatz project."
		author = "FireEye"
		id = "e160b75d-cc39-5e16-86e1-cba9fe64a6b6"
		date = "2020-12-09"
		modified = "2020-12-09"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/rules/SAFETYKATZ/production/yara/HackTool_MSIL_SAFETYKATZ_4.yar#L4-L15"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b/LICENSE.txt"
		hash = "45736deb14f3a68e88b038183c23e597"
		logic_hash = "a02b4acea691d485f427ed26487f2f601065901324a8dcd6cd8de9502d8cd897"
		score = 75
		quality = 73
		tags = "FILE"
		rev = 3

	strings:
		$typelibguid1 = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $typelibguid1
}
