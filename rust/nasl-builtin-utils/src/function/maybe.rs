use nasl_syntax::NaslValue;

use crate::FunctionErrorKind;

use super::FromNaslValue;

/// Represents an input to a function that is supposed to be
/// of a particular type, but it being of a different type
/// will be handled by ignoring the value (and probably returning
/// `None` or some sentinel value), instead of producing an error.
pub struct Maybe<T>(Option<T>);

impl<'a, T: FromNaslValue<'a>> FromNaslValue<'a> for Maybe<T> {
    fn from_nasl_value(value: &'a NaslValue) -> Result<Self, FunctionErrorKind> {
        Ok(Self(T::from_nasl_value(value).ok()))
    }
}

impl<T> From<Maybe<T>> for Option<T> {
    fn from(value: Maybe<T>) -> Self {
        value.0
    }
}

impl<T> Maybe<T> {
    /// Map a Maybe<T> to an Option<S> using a function
    /// f: T -> S.
    pub fn map<S>(self, f: impl Fn(T) -> S) -> Option<S>{
        self.0.map(f)
    }

    /// Transform the Maybe into an Option
    pub fn as_option(self) -> Option<T> {
        self.0
    }
}
