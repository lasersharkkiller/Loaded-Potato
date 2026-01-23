rule WEBSHELL_H4ntu_Shell_Powered_Tsoi_2 {
   meta:
      description = "PHP Webshells Github Archive - file h4ntu shell [powered by tsoi].php"
      author = "Florian Roth"
      date = "2014-04-06"
      modified = "2025-03-21"
      old_rule_name = "WebShell_h4ntu_shell__powered_by_tsoi_"
      hash = "cbca8cd000e705357e2a7e0cf8262678706f18f9"
   strings:
      $s1 = "<title>h4ntu shell [powered by tsoi]</title>" fullword
      $s2 = "$uname = posix_uname( );" fullword
      $s3 = "if(!$whoami)$whoami=exec(\"whoami\");" fullword
      $s4 = "echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>"
   condition:
      filesize <2MB and 2 of them
}
