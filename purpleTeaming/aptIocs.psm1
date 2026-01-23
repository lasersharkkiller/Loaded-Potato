<#
.Module Name
    ThreatActorIOCs
.SYNOPSIS
    Bulk Threat Intelligence Harvester (VirusTotal + Cybersixgill).
    v11.6 - UPDATE:
     - Added 'LAPSUS$' and 'DragonForce' to e-Crime.
     - Added 'Restic' (Backup tool used by INC) to Dual-Use Tools.
     - Retains all previous targets (SLH members, Voidlink, etc.).
#>

function Get-ThreatActorIOCs {
    [CmdletBinding()]
    param (
        [string]$StartDate = ((Get-Date).AddYears(-6).ToString("yyyy-MM-dd")),
        [string]$SpecificActor = $null,
        [int]$MaxSamples = 500
    )

    process {
        # --- 1. DEFINE THE MASTER CONFIGURATION ---
        $MasterConfig = @(
            # =========================================================
            # SECTION 1: NATION STATE (APT)
            # =========================================================

            # === CHINA ===
            @{ 
                Name = "Velvet Ant"; Country = "China"; Type = "APT"; 
                Aliases = @("Velvet Ant"); 
                LinkedTools = @("VelvetSting", "VelvetTap", "PlugX", "EarthWorm", "Impacket") 
            },
            @{ 
                Name = "Flax Typhoon"; Country = "China"; Type = "APT"; 
                Aliases = @("Flax Typhoon", "Ethereal Panda", "RedJuliett"); 
                LinkedTools = @("China Chopper", "JuicyPotato", "BadPotato", "SoftEther", "Metasploit") 
            },
            @{ Name = "UAT-8837"; Country = "China"; Type = "APT"; Aliases = @("UAT-8837"); LinkedTools = @("GoTokenTheft", "EarthWorm", "DWAgent", "SharpHound", "Impacket", "GoExec", "Rubeus", "Certipy") },
            @{ Name = "Salt Typhoon"; Country = "China"; Type = "APT"; Aliases = @("Salt Typhoon", "GhostEmperor", "FamousSparrow"); LinkedTools = @("GhostSpider", "Demodex", "ShadowPad") },
            @{ Name = "Storm-2603"; Country = "China"; Type = "APT"; Aliases = @("Storm-2603", "CL-CRI-1040", "Gold Salem"); LinkedTools = @("AK47 C2", "ToolShell", "Impacket") },
            @{ Name = "Earth Krahang"; Country = "China"; Type = "APT"; Aliases = @("Earth Krahang"); LinkedTools = @("RESHELL", "XDealer", "Cobalt Strike", "Fscan") },
            @{ Name = "UAT-7290"; Country = "China"; Type = "APT"; Aliases = @("UAT-7290", "Red Foxtrot"); LinkedTools = @("RushDrop", "SilentRaid", "DriveSwitch", "ShadowPad") },
            @{ Name = "UNC3886"; Country = "China"; Type = "APT"; Aliases = @("UNC3886", "Fire Ant"); LinkedTools = @("TinyShell", "Reptile", "Medusa") },
            @{ Name = "Volt Typhoon"; Country = "China"; Type = "APT"; Aliases = @("Volt Typhoon", "Bronze Silhouette"); LinkedTools = @("KV-Botnet", "Impacket", "EarthWorm", "FastReverseProxy") },
            @{ Name = "APT1"; Country = "China"; Type = "APT"; Aliases = @("APT1", "Comment Crew", "Comment Panda"); LinkedTools = @("PoisonIvy", "PlugX") },
            @{ Name = "APT10"; Country = "China"; Type = "APT"; Aliases = @("APT10", "Stone Panda", "MenuPass"); LinkedTools = @("PlugX", "QuasarRAT", "Chisel") },
            @{ Name = "APT27"; Country = "China"; Type = "APT"; Aliases = @("APT27", "Emissary Panda", "LuckyMouse"); LinkedTools = @("PlugX", "HyperBro", "Fscan") },
            @{ Name = "APT31"; Country = "China"; Type = "APT"; Aliases = @("APT31", "Zirconium", "Judgment Panda"); LinkedTools = @("SOGU", "LuckyBird") },
            @{ Name = "APT41"; Country = "China"; Type = "APT"; Aliases = @("APT41", "Barium", "Winnti", "Wicked Panda"); LinkedTools = @("ShadowPad", "Cobalt Strike", "Winnti", "EarthWorm") },
            @{ Name = "Aquatic Panda"; Country = "China"; Type = "APT"; Aliases = @("Aquatic Panda", "Earth Lusca"); LinkedTools = @("ShadowPad", "Winnti") },
            @{ Name = "BlackTech"; Country = "China"; Type = "APT"; Aliases = @("BlackTech", "Palmerworm"); LinkedTools = @("Kivars", "Pled", "Consock") },
            @{ Name = "Gallium"; Country = "China"; Type = "APT"; Aliases = @("Gallium", "Soft Cell"); LinkedTools = @("PingPull", "Gh0st RAT") },
            @{ Name = "Hafnium"; Country = "China"; Type = "APT"; Aliases = @("Hafnium", "Silk Typhoon"); LinkedTools = @("Tarrask", "China Chopper") },
            @{ Name = "Ke3chang"; Country = "China"; Type = "APT"; Aliases = @("Ke3chang", "APT15", "Vixen Panda"); LinkedTools = @("Okrum", "Ketrican", "RoyalDNS") },
            @{ Name = "Mustang Panda"; Country = "China"; Type = "APT"; Aliases = @("Mustang Panda", "Bronze President"); LinkedTools = @("PlugX", "Cobalt Strike") },

            # === IRAN ===
            @{ Name = "Agrius"; Country = "Iran"; Type = "APT"; Aliases = @("Agrius", "Pink Sandstorm") },
            @{ Name = "APT33"; Country = "Iran"; Type = "APT"; Aliases = @("APT33", "Elfin", "Holmium") },
            @{ Name = "APT34 (OilRig)"; Country = "Iran"; Type = "APT"; Aliases = @("APT34", "OilRig", "Helix Kitten") },
            @{ Name = "APT35 (Charming Kitten)"; Country = "Iran"; Type = "APT"; Aliases = @("APT35", "Charming Kitten", "Phosphorus") },
            @{ Name = "APT42"; Country = "Iran"; Type = "APT"; Aliases = @("APT42", "Mint Sandstorm", "TA453") },
            @{ Name = "Cleaver"; Country = "Iran"; Type = "APT"; Aliases = @("Cleaver", "Operation Cleaver") },
            @{ Name = "CyberAv3ngers"; Country = "Iran"; Type = "APT"; Aliases = @("CyberAv3ngers") },
            @{ Name = "Fox Kitten"; Country = "Iran"; Type = "APT"; Aliases = @("Fox Kitten", "Pioneer Kitten") },
            @{ Name = "MuddyWater"; Country = "Iran"; Type = "APT"; Aliases = @("MuddyWater", "DEV-1084", "Seedworm"); LinkedTools = @("Ligolo", "Chisel") },

            # === NORTH KOREA ===
            @{ Name = "Andariel"; Country = "NorthKorea"; Type = "APT"; Aliases = @("Andariel", "Stonefly", "Onyx Sleet") },
            @{ Name = "APT37"; Country = "NorthKorea"; Type = "APT"; Aliases = @("APT37", "Reaper", "ScarCruft") },
            @{ Name = "APT38"; Country = "NorthKorea"; Type = "APT"; Aliases = @("APT38", "BlueNoroff", "BeagleBoyz") },
            @{ Name = "Famous Chollima"; Country = "NorthKorea"; Type = "APT"; Aliases = @("Famous Chollima", "Nickel Tapestry") },
            @{ Name = "Kimsuky"; Country = "NorthKorea"; Type = "APT"; Aliases = @("Kimsuky", "Velvet Chollima", "Black Banshee") },
            @{ Name = "Lazarus"; Country = "NorthKorea"; Type = "APT"; Aliases = @("Lazarus Group", "Hidden Cobra", "Zinc"); LinkedTools = @("Manuscrypt", "MimiKatz") },

            # === RUSSIA ===
            @{ Name = "ALLANITE"; Country = "Russia"; Type = "APT"; Aliases = @("ALLANITE", "Dragonfly", "Energetic Bear") },
            @{ Name = "APT28"; Country = "Russia"; Type = "APT"; Aliases = @("APT28", "Fancy Bear", "Forest Blizzard"); LinkedTools = @("Mimikatz", "Impacket", "Chisel") },
            @{ Name = "APT29"; Country = "Russia"; Type = "APT"; Aliases = @("APT29", "Cozy Bear", "Midnight Blizzard") },
            @{ Name = "Gamaredon"; Country = "Russia"; Type = "APT"; Aliases = @("Gamaredon", "Primitive Bear", "Shuckworm") },
            @{ Name = "Sandworm"; Country = "Russia"; Type = "APT"; Aliases = @("Sandworm", "Voodoo Bear", "Seashell Blizzard"); LinkedTools = @("BlackEnergy", "Industroyer", "Chisel") },
            @{ Name = "Silence"; Country = "Russia"; Type = "APT"; Aliases = @("Silence", "Whisper Spider") },
            @{ Name = "Star Blizzard"; Country = "Russia"; Type = "APT"; Aliases = @("Star Blizzard", "ColdRiver", "Callisto") },
            @{ Name = "Turla"; Country = "Russia"; Type = "APT"; Aliases = @("Turla", "Venomous Bear", "Waterbug") },

            # === VIETNAM / S. AMERICA ===
            @{ Name = "APT32"; Country = "Vietnam"; Type = "APT"; Aliases = @("APT32", "OceanLotus"); LinkedTools = @("Cobalt Strike", "Kerrdown") },
            @{ Name = "Blind Eagle"; Country = "SouthAmerica"; Type = "APT"; Aliases = @("Blind Eagle", "APT-C-36") },

            # === E-CRIME ===
            @{ Name = "ShinyHunters"; Country = "eCrime"; Type = "APT"; Aliases = @("ShinyHunters", "ShinyCorp", "UNC6040"); LinkedTools = @("Impacket", "Salesforce Data Loader", "Mimikatz") },
            @{ Name = "LAPSUS$"; Country = "eCrime"; Type = "APT"; Aliases = @("LAPSUS$", "DEV-0537", "Lapsus Group"); LinkedTools = @("Mimikatz", "ADExplorer") },
            @{ Name = "DragonForce"; Country = "eCrime"; Type = "APT"; Aliases = @("DragonForce", "DragonForce Ransomware") },
            @{ Name = "RansomHub"; Country = "eCrime"; Type = "APT"; Aliases = @("RansomHub", "Cyclops", "Knight"); LinkedTools = @("Cobalt Strike", "Mimikatz", "Chisel", "AnyDesk") },
            @{ Name = "Play Ransomware"; Country = "eCrime"; Type = "APT"; Aliases = @("Play Ransomware", "PlayCrypt"); LinkedTools = @("Cobalt Strike", "AdFind", "Grixba", "SystemBC") },
            @{ Name = "Akira"; Country = "eCrime"; Type = "APT"; Aliases = @("Akira", "Storm-1567") },
            @{ Name = "BlackByte"; Country = "eCrime"; Type = "APT"; Aliases = @("BlackByte", "Hecamede") },
            @{ Name = "Carbanak"; Country = "eCrime"; Type = "APT"; Aliases = @("Carbanak", "Anunak") },
            @{ Name = "FIN6"; Country = "eCrime"; Type = "APT"; Aliases = @("FIN6", "Skeleton Spider") },
            @{ Name = "FIN7"; Country = "eCrime"; Type = "APT"; Aliases = @("FIN7", "Carbon Spider") },
            @{ Name = "Scattered Spider"; Country = "eCrime"; Type = "APT"; Aliases = @("Scattered Spider", "Octo Tempest", "0ktapus"); LinkedTools = @("BlackCat", "Rubeus", "Mimikatz", "Rhadamanthys") },
            @{ Name = "TeamTNT"; Country = "eCrime"; Type = "APT"; Aliases = @("TeamTNT") },
            @{ Name = "Wizard Spider"; Country = "eCrime"; Type = "APT"; Aliases = @("Wizard Spider", "TrickBot", "Ryuk") },

            # =========================================================
            # SECTION 2: MALWARE FAMILIES & TOOLS
            # =========================================================

            # --- A. RANSOMWARE (BIG GAME HUNTING) ---
            @{ Name = "LockBit";          Type = "Malware"; Aliases = @("LockBit", "LockBit 3.0", "LockBit Black") },
            @{ Name = "BlackCat";         Type = "Malware"; Aliases = @("BlackCat", "ALPHV", "Nokoyawa") },
            @{ Name = "BlackBasta";       Type = "Malware"; Aliases = @("BlackBasta") },
            @{ Name = "Rhysida";          Type = "Malware"; Aliases = @("Rhysida", "Rhysida Ransomware") },
            @{ Name = "8Base";            Type = "Malware"; Aliases = @("8Base") },
            @{ Name = "Phobos";           Type = "Malware"; Aliases = @("Phobos", "Eking") },
            @{ Name = "MedusaLocker";     Type = "Malware"; Aliases = @("MedusaLocker", "Medusa Ransomware") },
            @{ Name = "BianLian";         Type = "Malware"; Aliases = @("BianLian") },
            @{ Name = "Mallox";           Type = "Malware"; Aliases = @("Mallox", "TargetCompany") },
            @{ Name = "Inc Ransom";       Type = "Malware"; Aliases = @("Inc Ransom", "IncRansom") },
            @{ Name = "Qilin";            Type = "Malware"; Aliases = @("Qilin", "Agenda Ransomware") },
            @{ Name = "Cactus";           Type = "Malware"; Aliases = @("Cactus Ransomware") },
            @{ Name = "Cuba";             Type = "Malware"; Aliases = @("Cuba Ransomware", "Fidel") },
            @{ Name = "Royal";            Type = "Malware"; Aliases = @("Royal Ransomware") },
            @{ Name = "Clop";             Type = "Malware"; Aliases = @("Clop", "Cl0p") },
            @{ Name = "AvosLocker";       Type = "Malware"; Aliases = @("AvosLocker") },
            @{ Name = "Hive";             Type = "Malware"; Aliases = @("Hive Ransomware") },
            @{ Name = "Knight";           Type = "Malware"; Aliases = @("Knight Ransomware", "Cyclops") },
            @{ Name = "NoEscape";         Type = "Malware"; Aliases = @("NoEscape") },
            @{ Name = "DarkSide";         Type = "Malware"; Aliases = @("DarkSide") },
            @{ Name = "Conti";            Type = "Malware"; Aliases = @("Conti") },
            @{ Name = "Babuk";            Type = "Malware"; Aliases = @("Babuk", "Babyk") },
            @{ Name = "Wannacry";         Type = "Malware"; Aliases = @("Wannacry", "WanaCrypt0r") },
            @{ Name = "Dharma";           Type = "Malware"; Aliases = @("Dharma", "Crysis") },
            @{ Name = "StopDjvu";         Type = "Malware"; Aliases = @("StopDjvu", "STOP Ransomware") },

            # --- B. INFOSTEALERS (MAAS) ---
            @{ Name = "Lumma Stealer";    Type = "Malware"; Aliases = @("Lumma", "LummaC2") },
            @{ Name = "RedLine";          Type = "Malware"; Aliases = @("RedLine", "RedLine Stealer") },
            @{ Name = "Vidar";            Type = "Malware"; Aliases = @("Vidar", "Vidar Stealer") },
            @{ Name = "Rhadamanthys";     Type = "Malware"; Aliases = @("Rhadamanthys") },
            @{ Name = "Stealc";           Type = "Malware"; Aliases = @("Stealc") },
            @{ Name = "RisePro";          Type = "Malware"; Aliases = @("RisePro") },
            @{ Name = "Meduza";           Type = "Malware"; Aliases = @("Meduza Stealer") },
            @{ Name = "Atomic Stealer";   Type = "Malware"; Aliases = @("Atomic Stealer", "AMOS", "Atomic macOS") },
            @{ Name = "Raccoon";          Type = "Malware"; Aliases = @("Raccoon Stealer", "RecordBreaker") },
            @{ Name = "Meta Stealer";     Type = "Malware"; Aliases = @("Meta Stealer") },
            @{ Name = "Aurora";           Type = "Malware"; Aliases = @("Aurora Stealer", "Aurora Go") },
            @{ Name = "Ducktail";         Type = "Malware"; Aliases = @("Ducktail") },
            @{ Name = "Graphiron";        Type = "Malware"; Aliases = @("Graphiron") },
            @{ Name = "Mars Stealer";     Type = "Malware"; Aliases = @("Mars Stealer") },
            @{ Name = "BlackGuard";       Type = "Malware"; Aliases = @("BlackGuard") },
            @{ Name = "Echelon";          Type = "Malware"; Aliases = @("Echelon Stealer") },
            @{ Name = "StormKitty";       Type = "Malware"; Aliases = @("StormKitty") },
            @{ Name = "Predator";         Type = "Malware"; Aliases = @("Predator The Thief") },
            @{ Name = "Azorult";          Type = "Malware"; Aliases = @("Azorult") },

            # --- C. LOADERS & DROPPERS (INITIAL ACCESS) ---
            @{ Name = "Latrodectus";      Type = "Malware"; Aliases = @("Latrodectus", "BlackWidow", "IceNova") },
            @{ Name = "Pikabot";          Type = "Malware"; Aliases = @("Pikabot") },
            @{ Name = "SocGholish";       Type = "Malware"; Aliases = @("SocGholish", "FakeUpdates") },
            @{ Name = "DarkGate";         Type = "Malware"; Aliases = @("DarkGate") },
            @{ Name = "GuLoader";         Type = "Malware"; Aliases = @("GuLoader", "CloudEyE") },
            @{ Name = "GootLoader";       Type = "Malware"; Aliases = @("GootLoader", "Gootkit") },
            @{ Name = "Bumblebee";        Type = "Malware"; Aliases = @("Bumblebee", "ColdTrain") },
            @{ Name = "IcedID";           Type = "Malware"; Aliases = @("IcedID", "BokBot") },
            @{ Name = "SystemBC";         Type = "Malware"; Aliases = @("SystemBC", "Coroxy") },
            @{ Name = "SmokeLoader";      Type = "Malware"; Aliases = @("SmokeLoader", "Dofoil") },
            @{ Name = "PrivateLoader";    Type = "Malware"; Aliases = @("PrivateLoader") },
            @{ Name = "Amadey";           Type = "Malware"; Aliases = @("Amadey", "Amadey Bot") },
            @{ Name = "Emotet";           Type = "Malware"; Aliases = @("Emotet", "Geodo", "Heodo") },
            @{ Name = "QakBot";           Type = "Malware"; Aliases = @("QakBot", "QBot", "Pinkslipbot") },
            @{ Name = "TrickBot";         Type = "Malware"; Aliases = @("TrickBot") },
            @{ Name = "Dridex";           Type = "Malware"; Aliases = @("Dridex") },
            @{ Name = "ZLoader";          Type = "Malware"; Aliases = @("ZLoader", "SilentNight") },
            @{ Name = "Ursnif";           Type = "Malware"; Aliases = @("Ursnif", "Gozi", "ISFB") },

            # --- D. RATs (REMOTE ACCESS TROJANS) ---
            @{ Name = "Agent Tesla";      Type = "Malware"; Aliases = @("Agent Tesla", "AgentTesla") },
            @{ Name = "AsyncRAT";         Type = "Malware"; Aliases = @("AsyncRAT") },
            @{ Name = "Remcos";           Type = "Malware"; Aliases = @("Remcos", "RemcosRAT") },
            @{ Name = "NjRAT";            Type = "Malware"; Aliases = @("NjRAT", "Bladabindi") },
            @{ Name = "XWorm";            Type = "Malware"; Aliases = @("XWorm") },
            @{ Name = "NanoCore";         Type = "Malware"; Aliases = @("NanoCore") },
            @{ Name = "QuasarRAT";        Type = "Malware"; Aliases = @("QuasarRAT", "Quasar") },
            @{ Name = "FormBook";         Type = "Malware"; Aliases = @("FormBook") },
            @{ Name = "XLoader";          Type = "Malware"; Aliases = @("XLoader", "FormBook") },
            @{ Name = "WarzoneRAT";       Type = "Malware"; Aliases = @("WarzoneRAT", "Ave Maria") },
            @{ Name = "BitRAT";           Type = "Malware"; Aliases = @("BitRAT") },
            @{ Name = "DcRAT";            Type = "Malware"; Aliases = @("DcRAT") },
            @{ Name = "OrcusRAT";         Type = "Malware"; Aliases = @("OrcusRAT") },
            @{ Name = "RevengeRAT";       Type = "Malware"; Aliases = @("RevengeRAT") },
            @{ Name = "StrRAT";           Type = "Malware"; Aliases = @("StrRAT") },
            @{ Name = "Parallax";         Type = "Malware"; Aliases = @("Parallax RAT") },
            @{ Name = "NetWire";          Type = "Malware"; Aliases = @("NetWire") },
            @{ Name = "ModeloRAT";        Type = "Malware"; Aliases = @("ModeloRAT") },

            # --- E. LINUX & CLOUD THREATS ---
            @{ Name = "Mirai";            Type = "Malware"; Aliases = @("Mirai", "Mirai Botnet") },
            @{ Name = "XorDDoS";          Type = "Malware"; Aliases = @("XorDDoS") },
            @{ Name = "Kinsing";          Type = "Malware"; Aliases = @("Kinsing", "H2Miner") },
            @{ Name = "Tsunami";          Type = "Malware"; Aliases = @("Tsunami", "Kaiten") },
            @{ Name = "Gafgyt";           Type = "Malware"; Aliases = @("Gafgyt", "Bashlite") },
            @{ Name = "Mozi";             Type = "Malware"; Aliases = @("Mozi") },
            @{ Name = "TeamTNT Tools";    Type = "Malware"; Aliases = @("TeamTNT", "Hildegard") },
            @{ Name = "CoinMiner";        Type = "Malware"; Aliases = @("CoinMiner", "XMRig") },
            @{ Name = "DreamBus";         Type = "Malware"; Aliases = @("DreamBus") },
            @{ Name = "Sysrv";            Type = "Malware"; Aliases = @("Sysrv", "Sysrv-hello") },

            # --- F. APT-SPECIFIC & BESPOKE TOOLS ---
            @{ Name = "GoTokenTheft";     Type = "Malware"; Aliases = @("GoTokenTheft", "token-theft") },
            @{ Name = "EarthWorm";        Type = "Malware"; Aliases = @("EarthWorm", "EW_Tunnel", "ew_linux", "ew_win") },
            @{ Name = "GhostSpider";      Type = "Malware"; Aliases = @("GhostSpider Backdoor") },
            @{ Name = "Demodex";          Type = "Malware"; Aliases = @("Demodex Rootkit") },
            @{ Name = "RESHELL";          Type = "Malware"; Aliases = @("RESHELL") },
            @{ Name = "XDealer";          Type = "Malware"; Aliases = @("XDealer", "Luoyu") },
            @{ Name = "RushDrop";         Type = "Malware"; Aliases = @("RushDrop", "ChronosRAT") },
            @{ Name = "SilentRaid";       Type = "Malware"; Aliases = @("SilentRaid", "MystRodX") },
            @{ Name = "TinyShell";        Type = "Malware"; Aliases = @("TinyShell", "TinySH") },
            @{ Name = "Reptile";          Type = "Malware"; Aliases = @("Reptile Rootkit") },
            @{ Name = "ShadowPad";        Type = "Malware"; Aliases = @("ShadowPad", "PoisonPlug") },
            @{ Name = "Winnti";           Type = "Malware"; Aliases = @("Winnti Malware") },
            @{ Name = "PlugX";            Type = "Malware"; Aliases = @("PlugX", "Korplug") },
            @{ Name = "Kivars";           Type = "Malware"; Aliases = @("Kivars") },
            @{ Name = "Okrum";            Type = "Malware"; Aliases = @("Okrum") },
            @{ Name = "KV-Botnet";        Type = "Malware"; Aliases = @("KV-Botnet", "JDYFJ Botnet") },
            @{ Name = "Voidlink";         Type = "Malware"; Aliases = @("Voidlink") },

            # --- G. OFFENSIVE SECURITY / DUAL-USE TOOLS ---
            @{ Name = "Cobalt Strike";    Type = "Malware"; Aliases = @("Cobalt Strike", "Beacon") },
            @{ Name = "Sliver";           Type = "Malware"; Aliases = @("Sliver C2", "Sliver Implant") },
            @{ Name = "Brute Ratel";      Type = "Malware"; Aliases = @("Brute Ratel", "BRC4") },
            @{ Name = "Havoc";            Type = "Malware"; Aliases = @("Havoc C2", "Havoc Demon") },
            @{ Name = "Mythic";           Type = "Malware"; Aliases = @("Mythic C2") },
            @{ Name = "Maestro";          Type = "Malware"; Aliases = @("Maestro", "Maestro Toolkit") },
            @{ Name = "Mimikatz";         Type = "Malware"; Aliases = @("Mimikatz", "sekurlsa") },
            @{ Name = "Impacket";         Type = "Malware"; Aliases = @("Impacket", "secretsdump", "psexec.py", "wmiexec.py") },
            @{ Name = "Rubeus";           Type = "Malware"; Aliases = @("Rubeus", "Kerberos abuse") },
            @{ Name = "Certipy";          Type = "Malware"; Aliases = @("Certipy") },
            @{ Name = "SharpHound";       Type = "Malware"; Aliases = @("SharpHound", "BloodHound Collector") },
            @{ Name = "GoExec";           Type = "Malware"; Aliases = @("GoExec", "goexec") },
            @{ Name = "DWAgent";          Type = "Malware"; Aliases = @("DWAgent", "DWService") },
            @{ Name = "Chisel";           Type = "Malware"; Aliases = @("Chisel", "Chisel Tunnel") },
            @{ Name = "Fscan";            Type = "Malware"; Aliases = @("Fscan", "Fscan tool") },
            @{ Name = "Rclone";           Type = "Malware"; Aliases = @("Rclone", "Rclone tool") },
            @{ Name = "AnyDesk";          Type = "Malware"; Aliases = @("AnyDesk", "AnyDesk abuse") },
            @{ Name = "NetSupport";       Type = "Malware"; Aliases = @("NetSupport Manager", "NetSupport RAT") },
            @{ Name = "Ligolo";           Type = "Malware"; Aliases = @("Ligolo", "Ligolo-ng") },
            @{ Name = "Restic";           Type = "Malware"; Aliases = @("Restic", "restic backup") },
            @{ Name = "Metasploit";       Type = "Malware"; Aliases = @("Metasploit", "Meterpreter") }
        )

        Write-Host "==========================================" -ForegroundColor Cyan
        Write-Host "    GLOBAL THREAT INTEL HARVESTER v11.6"
        Write-Host "    Total Targets: $($MasterConfig.Count) | Max Samples: $MaxSamples"
        Write-Host "==========================================" -ForegroundColor Cyan
        
        # --- 2. AUTHENTICATION ---
        if (-not (Get-Module -Name "Microsoft.PowerShell.SecretManagement")) {
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
        }

        try {
            $VTKey     = (Get-Secret -Name 'VT_API_Key_1' -AsPlainText).Trim()
            $SixID     = (Get-Secret -Name 'Cyber6Gil_Client_Id' -AsPlainText).Trim()
            $SixSecret = (Get-Secret -Name 'Cyber6Gil_API_Key' -AsPlainText).Trim()
            
            if (-not $VTKey -or -not $SixID) { throw "Credentials missing in Vault." }

            $AuthBody = @{ grant_type="client_credentials"; client_id=$SixID; client_secret=$SixSecret }
            $Token = (Invoke-RestMethod -Method Post -Uri "https://api.cybersixgill.com/auth/token" -Body $AuthBody).access_token
            $SixHeaders = @{ "Authorization"="Bearer $Token"; "Content-Type"="application/json" }
            $VTHeaders  = @{ "x-apikey" = $VTKey; "accept" = "application/json" }
        }
        catch { Write-Error "STOPPING: Authentication Failed."; return }

        # --- 3. EXECUTION LOOP ---
        foreach ($Entry in $MasterConfig) {
            
            if ($SpecificActor -and ($Entry.Name -ne $SpecificActor)) { continue }

            $ActorName = $Entry.Name
            $Aliases   = $Entry.Aliases
            $Type      = $Entry.Type
            
            Write-Host "`n---------------------------------------------------"
            Write-Host "PROCESSING: $ActorName ($Type)" -ForegroundColor Yellow
            if ($Entry.LinkedTools) { Write-Host "Known Toolset: $($Entry.LinkedTools -join ', ')" -ForegroundColor DarkGray }
            
            # --- DYNAMIC FOLDER PATH ---
            $BaseRoot = "$PSScriptRoot\..\apt\c6g"
            if ($Type -eq "APT") {
                $TargetFolder = Join-Path -Path $BaseRoot -ChildPath "APTs\$($Entry.Country)\$($Entry.Name)"
            } else {
                $TargetFolder = Join-Path -Path $BaseRoot -ChildPath "Malware Families\$($Entry.Name)"
            }

            try { $TargetFolder = [System.IO.Path]::GetFullPath($TargetFolder) } catch {}
            if (-not (Test-Path $TargetFolder)) { New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null }

            # --- APPEND MODE ---
            $SafeName = $ActorName -replace '[\\/*?:"<>|]', ''
            $OutFile = Join-Path -Path $TargetFolder -ChildPath "${SafeName}_Master_Intel.csv"
            
            $ExistingData = @()
            if (Test-Path $OutFile) {
                try {
                    $ExistingData = Import-Csv $OutFile
                    Write-Host "    Loaded $($ExistingData.Count) existing records." -ForegroundColor Gray
                } catch {
                    Write-Warning "    Could not read existing CSV. Starting fresh."
                }
            }

            $Raw_IOCs = @()
            $HashCache = @{}

            # [A] VIRUSTOTAL HARVEST
            Write-Host " -> [VT] Searching..." -NoNewline
            
            # Prepare Query Batch
            $QueriesToRun = @()

            if ($Type -eq "APT") {
                foreach ($Alias in $Aliases) {
                    $QueriesToRun += [PSCustomObject]@{ Query = "threat_actor:`"$Alias`""; Type = "Strict"; Term = $Alias }
                }
            } else {
                # UPDATED (v11.4): Added 'family' and 'threat_label' for expanded coverage
                $CombinedAlias = ($Aliases | ForEach-Object { "engines:`"$_`" OR name:`"$_`" OR tags:`"$_`" OR caption:`"$_`" OR family:`"$_`" OR threat_label:`"$_`" " }) -join " OR "
                $QueriesToRun += [PSCustomObject]@{ Query = "($CombinedAlias)"; Type = "Bulk"; Term = "MalwareFamily" }
            }

            foreach ($Q in $QueriesToRun) {
                if ($Raw_IOCs.Count -ge $MaxSamples) { break }

                try {
                    $CurrentQuery = "$($Q.Query) AND fs:$StartDate+"
                    $Encoded = [Uri]::EscapeDataString($CurrentQuery)
                    # Limit 500, Newest First
                    $Uri = "https://www.virustotal.com/api/v3/intelligence/search?query=$Encoded&limit=500&order=first_submission_date-"
                    
                    $Response = Invoke-RestMethod -Uri $Uri -Headers $VTHeaders -Method Get -ErrorAction Stop
                    
                    if ($Response.data) {
                        foreach ($File in $Response.data) {
                            if ($Raw_IOCs.Count -ge $MaxSamples) { break }
                            
                            $SHA256 = $File.id
                            if ($File.attributes.md5)  { $HashCache[$File.attributes.md5]  = $SHA256 }
                            if ($File.attributes.sha1) { $HashCache[$File.attributes.sha1] = $SHA256 }

                            $Raw_IOCs += [PSCustomObject]@{
                                Date=$([DateTimeOffset]::FromUnixTimeSeconds($File.attributes.first_submission_date).DateTime.ToString("yyyy-MM-dd"));
                                Source="VirusTotal"; Actor=$ActorName; IOCType="SHA256"; IOCValue=$SHA256;
                                Context=$File.attributes.meaningful_name; Link="https://www.virustotal.com/gui/file/$($SHA256)"
                            }
                        }
                    } else {
                        # SMART FALLBACK
                        if ($Q.Type -eq "Strict") {
                            Write-Host " [0 hits, trying fallback]" -NoNewline -ForegroundColor DarkGray
                            $FallbackQuery = "`"$($Q.Term)`" AND fs:$StartDate+"
                            $EncodedFallback = [Uri]::EscapeDataString($FallbackQuery)
                            $FallbackUri = "https://www.virustotal.com/api/v3/intelligence/search?query=$EncodedFallback&limit=100&order=first_submission_date-"
                            
                            $FallbackResp = Invoke-RestMethod -Uri $FallbackUri -Headers $VTHeaders -Method Get -ErrorAction SilentlyContinue
                            
                            if ($FallbackResp.data) {
                                foreach ($File in $FallbackResp.data) {
                                    if ($Raw_IOCs.Count -ge $MaxSamples) { break }
                                    $SHA256 = $File.id
                                    if ($File.attributes.md5) { $HashCache[$File.attributes.md5] = $SHA256 }
                                    $Raw_IOCs += [PSCustomObject]@{
                                        Date=$([DateTimeOffset]::FromUnixTimeSeconds($File.attributes.first_submission_date).DateTime.ToString("yyyy-MM-dd"));
                                        Source="VirusTotal (Fallback)"; Actor=$ActorName; IOCType="SHA256"; IOCValue=$SHA256;
                                        Context="Text Match: $($Q.Term)"; Link="https://www.virustotal.com/gui/file/$($SHA256)"
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    # Continue silently
                }
            }

            if ($Raw_IOCs.Count -gt 0) { Write-Host " Found $($Raw_IOCs.Count)." -ForegroundColor Green } 
            else { Write-Host " Found 0." -ForegroundColor Gray }

            # [B] CYBERSIXGILL HARVEST
            Write-Host " -> [C6G] Searching..." -NoNewline
            $SixCount = 0
            
            if ($Type -eq "Malware") {
                $C6G_Url = "https://api.cybersixgill.com/threat_hunting/malware/ioc"
                $C6G_Key = "malware_name"
            } else {
                $C6G_Url = "https://api.cybersixgill.com/threat_hunting/apts/ioc"
                $C6G_Key = "apt_name"
            }

            foreach ($Alias in $Aliases) {
                if (($Raw_IOCs.Count + $SixCount) -ge $MaxSamples) { break }

                $Offset = 0; $PageLimit = 100; $MorePages = $true
                do {
                    if (($Raw_IOCs.Count + $SixCount) -ge $MaxSamples) { $MorePages = $false; break }

                    $PayloadMap = @{ pagination = @{ limit = $PageLimit; offset = $Offset } }
                    $PayloadMap[$C6G_Key] = $Alias
                    $Payload = $PayloadMap | ConvertTo-Json -Depth 5

                    try {
                        $Response = Invoke-RestMethod -Method Post -Uri $C6G_Url -Headers $SixHeaders -Body $Payload
                        if ($Response.objects) {
                            foreach ($Item in $Response.objects) {
                                if (($Raw_IOCs.Count + $SixCount) -ge $MaxSamples) { break }
                                
                                if ($Item.ioc_type -match "Hash|MD5|SHA") {
                                    $Raw_IOCs += [PSCustomObject]@{
                                        Date=$Item.ioc_last_seen; Source="Cybersixgill"; Actor=$ActorName;
                                        IOCType=$Item.ioc_type; IOCValue=$Item.ioc_value;
                                        Context="Confidence: $($Item.ioc_confidence)"; Link="N/A"
                                    }
                                    $SixCount++
                                }
                            }
                            $Offset += $PageLimit
                            if ($Response.objects.Count -lt $PageLimit) { $MorePages = $false }
                        } else { $MorePages = $false }
                    } catch { $MorePages = $false }
                } while ($MorePages)
            }
            Write-Host " Found $SixCount." -ForegroundColor Green

            # [C] NORMALIZATION & MERGE
            if ($Raw_IOCs.Count -gt 0) {
                Write-Host " -> Normalizing & Merging..." -ForegroundColor Cyan
                
                $FinalList = @()
                $UniqueUnknownHashes = @()

                foreach ($Row in $Raw_IOCs) {
                    if ($Row.IOCType -eq "SHA256") {
                        $FinalList += $Row
                    } 
                    elseif ($Row.IOCType -match "MD5|SHA1") {
                        if ($HashCache.ContainsKey($Row.IOCValue)) {
                            $Row.IOCType = "SHA256"
                            $Row.IOCValue = $HashCache[$Row.IOCValue]
                            $FinalList += $Row
                        } else {
                            $UniqueUnknownHashes += $Row.IOCValue
                            $FinalList += $Row 
                        }
                    } else {
                        $FinalList += $Row
                    }
                }

                # === DYNAMIC RESOLUTION (QUOTA SAVER) ===
                $ToQuery = $UniqueUnknownHashes | Select-Object -Unique
                if ($ToQuery) {
                    $Count = if ($ToQuery -is [array]) { $ToQuery.Count } else { 1 }
                    Write-Host "    Resolving $Count unique hashes via VirusTotal API..." -ForegroundColor Gray
                    
                    foreach ($Hash in $ToQuery) {
                        # 1. Double-check Cache (In case previous loop iteration found it)
                        if ($HashCache.ContainsKey($Hash)) { continue }

                        try {
                            $VTFileUri = "https://www.virustotal.com/api/v3/files/$Hash"
                            $VTRes = Invoke-RestMethod -Uri $VTFileUri -Headers $VTHeaders -Method Get -ErrorAction SilentlyContinue
                            
                            if ($VTRes.data.id) {
                                $NewSHA256 = $VTRes.data.id
                                
                                # 2. UPDATE CACHE IMMEDIATELY (Prevent Double-Billing)
                                if ($VTRes.data.attributes.md5)  { $HashCache[$VTRes.data.attributes.md5]  = $NewSHA256 }
                                if ($VTRes.data.attributes.sha1) { $HashCache[$VTRes.data.attributes.sha1] = $NewSHA256 }
                                $HashCache[$Hash] = $NewSHA256

                                foreach ($Row in $FinalList) {
                                    if ($Row.IOCValue -eq $Hash) {
                                        $Row.IOCType  = "SHA256"
                                        $Row.IOCValue = $NewSHA256
                                    }
                                }
                            }
                        } catch {}
                    }
                }

                $CombinedList = $FinalList + $ExistingData
                $UniqueSet = $CombinedList | Sort-Object Date -Descending | Group-Object IOCValue | ForEach-Object { $_.Group[0] }
                
                $UniqueSet | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
                
                Write-Host " -> SAVED: $OutFile" -ForegroundColor Cyan
                Write-Host "    New: $($Raw_IOCs.Count) | Total: $($UniqueSet.Count)" -ForegroundColor Gray
            } else {
                Write-Host " -> No new data found. Existing data preserved." -ForegroundColor Gray
            }
        }
        Write-Host "`n[BATCH COMPLETE]" -ForegroundColor Green
    }
}
Export-ModuleMember -Function Get-ThreatActorIOCs