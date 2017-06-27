import "magic"

rule lighttpd
{
	meta:
		software_name = "lighttpd"
		open_source = true
		website = "https://www.lighttpd.net/"
		description = "Lighttpd is a web-server optimized for low memory and cpu usage."
	strings:
		$a = /lighttpd-\d+\.\d+\.\d+/ nocase ascii wide
	condition:
		$a and ( magic.mime_type() != "text/plain" or test_flag )
}