const START: u8 = b'$';
const OPEN: u8 = b'{';
const CLOSE: u8 = b'}';

pub fn is_identifier_char(char: u8) -> bool {
  matches!(
    char,
    b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'0'..=b'9'
  )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Token<'a> {
  Lit(&'a str),
  Var(&'a str),
}

/// parse a variable from the start of the source string
fn parse_var(source: &str) -> Option<&str> {
  let buf = source.as_bytes();
  let start = *buf.first()?;
  if start != START {
    return None;
  }

  let open = *buf.get(1)?;
  if open != OPEN {
    return None;
  }

  let mut end = 2;
  while let Some(next) = buf.get(end) {
    if !is_identifier_char(*next) {
      break;
    }
    end += 1;
  }

  if end == 2 {
    return None;
  }

  let close = *buf.get(end)?;
  if close != CLOSE {
    return None;
  }

  Some(&source[2..end])
}

/// parse a literal from the start of the source string
fn parse_lit(source: &str) -> Option<&str> {
  let mut end = 0;

  loop {
    match source.get(end..) {
      None => break,
      Some("") => break,
      Some(slice) => match parse_var(slice) {
        Some(_) => break,
        None => end += 1,
      }
    }
  }
  
  if end == 0 {
    return None;
  }

  Some(&source[0..end])
}



/// An iterator that yields [`Token`]s from a string
pub struct TokensIter<'a> {
  source: &'a str,
  i: usize
} 

impl<'a> Iterator for TokensIter<'a> {
  type Item = Token<'a>;

  fn next(&mut self) -> Option<Self::Item> {
    
    use Token::*;

    if self.i >= self.source.len() {
      return None;
    }

    match parse_var(&self.source[self.i..]) {
      Some(ident) => {
        self.i += ident.len() + 3;
        Some(Var(ident))
      },
      None => match parse_lit(&self.source[self.i..]) {
        Some(lit) => {
          self.i += lit.len();
          Some(Lit(lit))
        },
        None => None,
      }
    }
  }
}

/// An iterator that yields [`Token`]s from a string
pub fn tokens(source: &str) -> TokensIter<'_> {
  TokensIter {
    source,
    i: 0,
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use Token::*;

  #[test]
  fn parse_var() {
    let cases: &[(&str, Option<&str>)] = &[
      ("${foo}", Some("foo")),
      ("${foo_bar} asd", Some("foo_bar")),
      ("${foo}${bar}   ", Some("foo")),
      ("${$none}", None),
      ("foo $${bar}", None),
      ("foo $${bar} ${baz}", None),
      ("foo $${bar} $${baz}", None),
    ];

    for (source, expected) in cases {
      let actual = super::parse_var(source);
      assert_eq!(actual, *expected, "{} failed", source);
    }
  }

  #[test]
  fn parse_lit() {
    let cases: &[(&str, Option<&str>)] = &[
      ("foo", Some("foo")),
      ("foo ${bar}", Some("foo ")),
      ("foo $${bar}", Some("foo $")),
      ("foo $${bar} ${baz}", Some("foo $")),
      ("foo $${bar} $${baz}", Some("foo $")),
      ("$bar asd a", Some("$bar asd a")),
      ("$foo${bar}${baz}$$", Some("$foo")),
    ];

    for (source, expected) in cases {
      let actual = super::parse_lit(source);
      assert_eq!(actual, *expected, "{} failed", source);
    }
  }


  #[test]
  fn tokens() {
    let cases: &[(&str, &[Token<'_>])] = &[
      ("${foo}", &[Var("foo")]), 
      ("foo ${bar}", &[Lit("foo "), Var("bar")]),
      ("foo ${bar} baz", &[Lit("foo "), Var("bar"), Lit(" baz")]),
      ("foo ${bar} ${baz}", &[Lit("foo "), Var("bar"), Lit(" "), Var("baz")]),
      ("foo $${bar}", &[Lit("foo $"), Var("bar")]),
      ("foo $${bar} ${baz}", &[Lit("foo $"), Var("bar"), Lit(" "), Var("baz")]),
      ("foo $${bar} $${baz}", &[Lit("foo $"), Var("bar"), Lit(" $"), Var("baz")]),
      ("${foo}${bar}${baz}$$", &[Var("foo"), Var("bar"), Var("baz"), Lit("$$")]),
      ("${foo}${bar}${baz}${literal", &[Var("foo"), Var("bar"), Var("baz"), Lit("${literal")]),
    ];

    for (source, expected) in cases {
      let actual = super::tokens(source).collect::<Vec<_>>();
      assert_eq!(actual, *expected, "{} failed", source);
    }
  }
}