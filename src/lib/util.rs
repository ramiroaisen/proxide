pub fn trim(data: &[u8]) -> &[u8] {
	trim_end(trim_start(data))
}

pub fn trim_start(data: &[u8]) -> &[u8] {
	if let Some(start) =data.iter().position(|x| !x.is_ascii_whitespace()) {
		&data[start..]
	} else {
		b""
	}
}

pub fn trim_end(data: &[u8]) -> &[u8] {
	if let Some(last) = data.iter().rposition(|x| !x.is_ascii_whitespace()) {
		&data[..last + 1]
	} else {
		b""
	}
}