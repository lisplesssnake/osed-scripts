def mapBadChars(sh):
	BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
	i = 0
	badIndex = []
	while i < len(sh):
		for c in BADCHARS:
			if sh[i] == c:
				badIndex.append(i)
		i=i+1
	return badIndex

def encodeShellcode(sh):
	BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
	REPLACECHARS = b"\xff\x10\x06\x07\x08\x05\x1f"
	encodedShell = sh
	for i in range(len(BADCHARS)):
		encodedShell = encodedShell.replace(pack("B", BADCHARS[i]), pack("B", REPLACECHARS[i]))
	return encodedShell
