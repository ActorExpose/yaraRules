rule GandCrab {
	meta:
		description = "Thanks to urlhaus for this sample: https://urlhaus.abuse.ch/url/327288/"
		in_the_wild = true
		md5_hash = "cfd00ed27a81ca43e2fa762aabf07f10"

	strings:
		$stringA = "ImmEscape"
        $encrypt = {45 6E 63 72 79 70 74 46 69 6C 65 57 00 00 00 00}
        $import = "cryptbase.dll"


	condition:
        $stringA and &encrypt or $encrypt and $import or $stringA and $import
}   



