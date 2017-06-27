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
		$a
}

rule another_test_rule
{
	meta:
		description = "test rule"
	strings:
		$a = "test"
	condition:
		$a
}

rule non_matching_rule
{
	meta:
		description = "non-matching test rule"
	strings:
		$a = "non-matching"
	condition:
		$a
}