pub mod duration;
pub mod header_name;
pub mod header_value;
pub mod sni;
pub mod status_code;

#[macro_export]
macro_rules! newtype {
  ($ty:ident => $inner:ty) => {
    impl ::std::ops::Deref for $ty {
      type Target = $inner;
      fn deref(&self) -> &Self::Target {
        &self.0
      }
    }

    impl ::std::ops::DerefMut for $ty {
      fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
      }
    }

    impl From<$inner> for $ty {
      fn from(value: $inner) -> $ty {
        $ty(value)
      }
    }

    impl From<$ty> for $inner {
      fn from(value: $ty) -> $inner {
        value.0
      }
    }
  };
}

#[macro_export]
macro_rules! json_schema_as {
  ($ty:ident => $target:ty) => {
    impl ::schemars::JsonSchema for $ty {
      fn schema_name() -> String {
        <$target>::schema_name()
      }

      fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        <$target>::json_schema(gen)
      }
    }
  };
}
