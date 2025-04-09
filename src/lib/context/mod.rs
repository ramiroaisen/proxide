use std::convert::Infallible;

pub trait Variable<'a>: Sized {
  type FromExprErr;
  fn from_expr(expr: &str) -> Result<Self, Self::FromExprErr>;

  type Context;
  type RenderErr;
  fn render(&self, buf: &mut String, context: &Self::Context) -> Result<(), Self::RenderErr>;
}

impl Variable<'_> for String {
  type FromExprErr = Infallible;
  fn from_expr(expr: &str) -> Result<Self, Self::FromExprErr> {
    Ok(expr.to_string())
  }

  type Context = ();
  type RenderErr = Infallible;
  fn render(&self, buf: &mut String, _context: &Self::Context) -> Result<(), Self::RenderErr> {
    buf.push_str("${");
    buf.push_str(self);
    buf.push('}');
    Ok(())
  }
}

pub trait Interpolation<'var, 'context> {
  type Var: Variable<'var>;
  type Context;
  fn render(
    &self,
    buf: &mut String,
    ctx: &Self::Context,
  ) -> Result<(), <Self::Var as Variable<'var>>::RenderErr>;

  fn render_to_string(
    &self,
    ctx: &Self::Context,
  ) -> Result<String, <Self::Var as Variable<'var>>::RenderErr> {
    let mut buf = String::new();
    self.render(&mut buf, ctx)?;
    Ok(buf)
  }
}
