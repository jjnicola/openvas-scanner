use std::ops::Range;

///! This module defines the TokenTypes as well as Token and extends Cursor with advance_token
use crate::cursor::Cursor;

/// Identifies if a string is quoteable or unquoteable
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringCategory {
    Quoteable,   // '..\''
    Unquoteable, // "..\"
}

/// Identifies if number is base10, base 8, hex or binary
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    Binary, // 0b010101
    Octal,  // 0123456780
    Base10, // 1234567890
    Hex,    //0x123456789ABCDEF0
}

impl Base {
    fn verify_binary(peeked: char) -> bool {
        peeked == '0' || peeked == '1'
    }

    fn verify_octal(peeked: char) -> bool {
        ('0'..='7').contains(&peeked)
    }

    fn verify_base10(peeked: char) -> bool {
        ('0'..='9').contains(&peeked)
    }

    fn verify_hex(peeked: char) -> bool {
        ('0'..='9').contains(&peeked)
            || ('A'..='F').contains(&peeked)
            || ('a'..='f').contains(&peeked)
    }
    pub(crate) fn verifier(self) -> impl Fn(char) -> bool {
        match self {
            Self::Binary => Self::verify_binary,
            Self::Octal => Self::verify_octal,
            Self::Base10 => Self::verify_base10,
            Self::Hex => Self::verify_hex,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnclosedCategory {
    String(StringCategory),
    Comment,
}
/// Is used to identify a Token
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    // Single-character tokens.
    LeftParen,         // (
    RightParen,        // )
    LeftBrace,         // [
    RightBrace,        // ]
    LeftCurlyBracket,  // {
    RightCurlyBracket, // }
    Comma,             // ,
    Dot,               // .
    Percent,           // %
    Semicolon,         // ;
    DoublePoint,       // :
    Tilde,             // ~
    Caret,             // ^
    // One or two character tokens
    Ampersand,          // &
    AmpersandAmpersand, // &&
    Pipe,               // |
    PipePipe,           // ||
    Bang,               // !
    BangEqual,          // !=
    BangTilde,          // !~
    Equal,              // =
    EqualEqual,         // ==
    EqualTilde,         // =~
    Greater,            // >
    GreaterGreater,     // >>
    GreaterEqual,       // >=
    GreaterLess,        // ><
    Less,               // <
    LessLess,           // <<
    LessEqual,          // <=
    Minus,              // -
    MinusMinus,         // --
    MinusEqual,         // -=
    Plus,               // +
    PlusEqual,          // +=
    PlusPlus,           // ++
    Slash,              // /
    SlashEqual,         // /=
    Star,               // *
    StarStar,           // **
    StarEqual,          // *=
    // Triple tokens
    GreaterGreaterGreater, // >>>
    GreaterGreaterEqual,   // >>=
    LessLessEqual,         // <<=
    LessLessLess,          // <<<
    GreaterBangLess,       // >!<
    // Tuple Tokens
    GreaterGreaterGreaterEqual, // >>>=
    LessLessLessEqual,          // <<<=
    // Variable size
    String(StringCategory), // "...\", multiline
    Number(Base),
    IllegalNumber(Base),
    Comment,
    Unclosed(UnclosedCategory),
    UnknownBase,
    UnknownSymbol, // used when the symbol is unknown
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Contains the TokenType as well as the position in form of Range<usize>
pub struct Token {
    category: Category,
    // using a tuple in favor of Range to have the possibility
    // to easily copy tokens rather than clone; to create a range for lookups
    // call range()
    position: (usize, usize),
}

impl Token {
    /// Returns the Category
    pub fn category(&self) -> Category {
        self.category
    }

    /// Returns the byte Range within original input
    pub fn range(&self) -> Range<usize> {
        let (start, end) = self.position;
        Range { start, end }
    }
}

/// Tokenizer uses a cursor to create tokens
#[derive(Clone)]
pub struct Tokenizer<'a> {
    // Is used to lookup keywords
    code: &'a str,
    cursor: Cursor<'a>,
}

// Is used to build Some(Token{ ... }) to make the match case within Iterator for Tokenizer easier to read
macro_rules! single_token {
    ($category:expr, $start:expr, $end:expr) => {
        Some(Token {
            category: $category,
            position: ($start, $end),
        })
    };
}

impl<'a> Tokenizer<'a> {
    /// Creates a new Tokenizer
    pub fn new(code: &'a str) -> Self {
        Tokenizer {
            code,
            cursor: Cursor::new(code),
        }
    }

    pub fn lookup(&self, range: Range<usize>) -> &'a str {
        &self.code[range]
    }

    // we break out of the macro since > can be parsed to:
    // >>>
    // >>=
    // >>>=
    // >!<
    // most operators don't have triple or tuple variant
    #[inline(always)]
    fn tokenize_greater(&mut self) -> Option<Token> {
        use Category::*;
        let start = self.cursor.len_consumed() - 1;
        let next = self.cursor.peek(0);
        match next {
            '=' => {
                self.cursor.advance();
                single_token!(GreaterEqual, start, self.cursor.len_consumed())
            }
            '<' => {
                self.cursor.advance();
                single_token!(GreaterLess, start, self.cursor.len_consumed())
            }
            '>' => {
                self.cursor.advance();
                let next = self.cursor.peek(0);
                match next {
                    '>' => {
                        self.cursor.advance();
                        if self.cursor.peek(0) == '=' {
                            self.cursor.advance();
                            return single_token!(
                                GreaterGreaterGreaterEqual,
                                start,
                                self.cursor.len_consumed()
                            );
                        }

                        single_token!(GreaterGreaterGreater, start, self.cursor.len_consumed())
                    }
                    '=' => {
                        self.cursor.advance();
                        single_token!(GreaterGreaterEqual, start, self.cursor.len_consumed())
                    }
                    _ => single_token!(GreaterGreater, start, self.cursor.len_consumed()),
                }
            }
            '!' if self.cursor.peek(1) == '<' => {
                self.cursor.advance();
                self.cursor.advance();
                single_token!(GreaterBangLess, start, self.cursor.len_consumed())
            }
            _ => single_token!(Greater, start, self.cursor.len_consumed()),
        }
    }

    // we break out of the macro since < can be parsed to:
    // <<<
    // <<=
    // <<<=
    // most operators don't have triple or tuple variant
    #[inline(always)]
    fn tokenize_less(&mut self) -> Option<Token> {
        use Category::*;
        let start = self.cursor.len_consumed() - 1;
        let next = self.cursor.peek(0);
        match next {
            '=' => {
                self.cursor.advance();
                single_token!(LessEqual, start, self.cursor.len_consumed())
            }
            '<' => {
                self.cursor.advance();
                let next = self.cursor.peek(0);
                match next {
                    '<' => {
                        self.cursor.advance();
                        if self.cursor.peek(0) == '=' {
                            self.cursor.advance();
                            return single_token!(
                                LessLessLessEqual,
                                start,
                                self.cursor.len_consumed()
                            );
                        }

                        single_token!(LessLessLess, start, self.cursor.len_consumed())
                    }
                    '=' => {
                        self.cursor.advance();
                        single_token!(LessLessEqual, start, self.cursor.len_consumed())
                    }
                    _ => single_token!(LessLess, start, self.cursor.len_consumed()),
                }
            }
            _ => single_token!(Less, start, self.cursor.len_consumed()),
        }
    }

    // Skips initital and ending string identifier ' || " and verifies that a string is closed
    #[inline(always)]
    fn tokenize_string(
        &mut self,
        string_category: StringCategory,
        predicate: impl FnMut(char) -> bool,
    ) -> Option<Token> {
        // we don't want the lookup to contain "
        let start = self.cursor.len_consumed();
        self.cursor.skip_while(predicate);
        if self.cursor.is_eof() {
            single_token!(
                Category::Unclosed(UnclosedCategory::String(string_category)),
                start,
                self.cursor.len_consumed()
            )
        } else {
            let result = single_token!(
                Category::String(string_category),
                start,
                self.cursor.len_consumed()
            );
            // skip "
            self.cursor.advance();
            result
        }
    }

    // checks if a number is binary, octal, base10 or hex
    #[inline(always)]
    pub fn tokenize_number(&mut self, mut start: usize, current: char) -> Option<Token> {
        use Base::*;
        let may_base = {
            if current == '0' {
                let peeked = self.cursor.peek(0);
                match peeked {
                    'b' => {
                        // jump over non numeric
                        self.cursor.advance();
                        // we don't need `0b` later
                        start += 2;
                        Some(Binary)
                    }
                    'x' => {
                        // jump over non numeric
                        self.cursor.advance();
                        // we don't need `0x` later
                        start += 2;
                        Some(Hex)
                    }
                    _ if peeked.is_numeric() => {
                        // we don't need leading 0 later
                        start += 1;
                        Some(Octal)
                    }
                    _ if peeked == '.' => Some(Base10),
                    _ => None,
                }
            } else {
                Some(Base10)
            }
        };
        if let Some(base) = may_base {
            self.cursor.skip_while(base.verifier());
            // we only allow float numbers in base10
            if base == Base10 && self.cursor.peek(0) == '.' && self.cursor.peek(1).is_numeric() {
                self.cursor.advance();
                self.cursor.skip_while(base.verifier());
            }
            if start == self.cursor.len_consumed() {
                single_token!(Category::IllegalNumber(base), start, start)
            } else {
                single_token!(Category::Number(base), start, self.cursor.len_consumed())
            }
        } else {
            single_token!(Category::UnknownBase, start, self.cursor.len_consumed())
        }
    }

    // checks if a starting slash is either an operator or a comment
    #[inline(always)]
    pub fn tokenize_slash(&mut self, start: usize) -> Option<Token> {
        match self.cursor.peek(0) {
            '=' => {
                self.cursor.advance();
                single_token!(Category::SlashEqual, start, self.cursor.len_consumed())
            }
            '/' => {
                self.cursor.skip_while(|c| c != '\n');
                single_token!(Category::Comment, start, self.cursor.len_consumed())
            }
            '*' => {
                let mut comments = 1;
                while comments > 0 {
                    self.cursor.skip_while(|c| c != '*' && c != '/');
                    self.cursor.advance();
                    // handles nested multiline comments
                    if let Some(c) = self.cursor.advance() {
                        if c == '/' {
                            comments -= 1;
                        } else if c == '*' {
                            comments += 1;
                        }
                    } else {
                        return single_token!(
                            Category::Unclosed(UnclosedCategory::Comment),
                            start,
                            self.cursor.len_consumed()
                        );
                    }
                }
                single_token!(Category::Comment, start, self.cursor.len_consumed())
            }
            _ => single_token!(Category::Slash, start, self.cursor.len_consumed()),
        }
    }
}

// Is used to simplify cases for double_tokens, instead of having to rewrite each match case for each double_token
// this macro can be used:
//'+' => double_token!(self.cursor, start, '+', '+', PlusPlus, '=', PlusEqual),
// within the Iterator implementation of Tokenizer
macro_rules! double_token {
    ($cursor:expr, $start:tt, $c:tt, $($l:tt, $bt:expr ), *) => {
        {
            // enforce start to be usize
            let next = $cursor.peek(0);
            match next {
                $($l => {
                  $cursor.advance();
                  single_token!($bt, $start, $cursor.len_consumed())
                }, )*
                _ => single_token!($c, $start, $cursor.len_consumed()),
            }
        }
    };
}

impl<'a> Iterator for Tokenizer<'a> {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> {
        use Category::*;
        self.cursor.skip_while(|c| c.is_whitespace());
        let start = self.cursor.len_consumed();
        match self.cursor.advance()? {
            '(' => single_token!(LeftParen, start, self.cursor.len_consumed()),
            ')' => single_token!(RightParen, start, self.cursor.len_consumed()),
            '[' => single_token!(LeftBrace, start, self.cursor.len_consumed()),
            ']' => single_token!(RightBrace, start, self.cursor.len_consumed()),
            '{' => single_token!(LeftCurlyBracket, start, self.cursor.len_consumed()),
            '}' => single_token!(RightCurlyBracket, start, self.cursor.len_consumed()),
            ',' => single_token!(Comma, start, self.cursor.len_consumed()),
            '.' => single_token!(Dot, start, self.cursor.len_consumed()),
            '-' => double_token!(self.cursor, start, Minus, '-', MinusMinus, '=', MinusEqual),
            '+' => double_token!(self.cursor, start, Plus, '+', PlusPlus, '=', PlusEqual),
            '%' => single_token!(Percent, start, self.cursor.len_consumed()),
            ';' => single_token!(Semicolon, start, self.cursor.len_consumed()),
            '/' => self.tokenize_slash(start),
            '*' => double_token!(self.cursor, start, Star, '*', StarStar, '=', StarEqual),
            ':' => single_token!(DoublePoint, start, self.cursor.len_consumed()),
            '~' => single_token!(Tilde, start, self.cursor.len_consumed()),
            '&' => double_token!(self.cursor, start, Ampersand, '&', AmpersandAmpersand),
            '|' => double_token!(self.cursor, start, Pipe, '|', PipePipe),
            '^' => single_token!(Caret, start, self.cursor.len_consumed()),
            '!' => double_token!(self.cursor, start, Bang, '=', BangEqual, '~', BangTilde),
            '=' => double_token!(self.cursor, start, Equal, '=', EqualEqual, '~', EqualTilde),
            '>' => self.tokenize_greater(),
            '<' => self.tokenize_less(),
            '"' => self.tokenize_string(StringCategory::Unquoteable, |c| c != '"'),
            '\'' => {
                let mut back_slash = false;
                self.tokenize_string(StringCategory::Quoteable, |c| {
                    if !back_slash && c == '\'' {
                        false
                    } else {
                        back_slash = c == '\\';
                        true
                    }
                })
            }

            current if current.is_numeric() => self.tokenize_number(start, current),
            _ => single_token!(UnknownSymbol, start, self.cursor.len_consumed()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_token(input: (Category, usize, usize)) -> Token {
        let (category, start, end) = input;
        Token {
            category,
            position: (start, end),
        }
    }

    // use macro instead of a method to have correct line numbers on failure
    macro_rules! verify_tokens {
        ($code:expr, $expected:expr) => {{
            let tokenizer = Tokenizer::new($code);
            let actual: Vec<Token> = tokenizer.clone().collect();
            let expected: Vec<Token> = $expected.iter().map(|x| build_token(*x)).collect();
            assert_eq!(actual, expected);
            (tokenizer, actual)
        }};
    }

    #[test]
    fn skip_white_space() {
        verify_tokens!("     (       ", vec![(Category::LeftParen, 5, 6)]);
    }

    #[test]
    fn single_token() {
        verify_tokens!("(", vec![(Category::LeftParen, 0, 1)]);
        verify_tokens!(")", vec![(Category::RightParen, 0, 1)]);
        verify_tokens!("[", vec![(Category::LeftBrace, 0, 1)]);
        verify_tokens!("]", vec![(Category::RightBrace, 0, 1)]);
        verify_tokens!("{", vec![(Category::LeftCurlyBracket, 0, 1)]);
        verify_tokens!("}", vec![(Category::RightCurlyBracket, 0, 1)]);
        verify_tokens!(",", vec![(Category::Comma, 0, 1)]);
        verify_tokens!(".", vec![(Category::Dot, 0, 1)]);
        verify_tokens!("-", vec![(Category::Minus, 0, 1)]);
        verify_tokens!("+", vec![(Category::Plus, 0, 1)]);
        verify_tokens!("%", vec![(Category::Percent, 0, 1)]);
        verify_tokens!(";", vec![(Category::Semicolon, 0, 1)]);
        verify_tokens!("/", vec![(Category::Slash, 0, 1)]);
        verify_tokens!("*", vec![(Category::Star, 0, 1)]);
        verify_tokens!(":", vec![(Category::DoublePoint, 0, 1)]);
        verify_tokens!("~", vec![(Category::Tilde, 0, 1)]);
        verify_tokens!("&", vec![(Category::Ampersand, 0, 1)]);
        verify_tokens!("|", vec![(Category::Pipe, 0, 1)]);
        verify_tokens!("^", vec![(Category::Caret, 0, 1)]);
    }

    #[test]
    fn double_token() {
        verify_tokens!("&", vec![(Category::Ampersand, 0, 1)]);
        verify_tokens!("&&", vec![(Category::AmpersandAmpersand, 0, 2)]);
        verify_tokens!("|", vec![(Category::Pipe, 0, 1)]);
        verify_tokens!("||", vec![(Category::PipePipe, 0, 2)]);
        verify_tokens!("!", vec![(Category::Bang, 0, 1)]);
        verify_tokens!("!=", vec![(Category::BangEqual, 0, 2)]);
        verify_tokens!("!~", vec![(Category::BangTilde, 0, 2)]);
        verify_tokens!("=", vec![(Category::Equal, 0, 1)]);
        verify_tokens!("==", vec![(Category::EqualEqual, 0, 2)]);
        verify_tokens!("=~", vec![(Category::EqualTilde, 0, 2)]);
        verify_tokens!(">", vec![(Category::Greater, 0, 1)]);
        verify_tokens!(">>", vec![(Category::GreaterGreater, 0, 2)]);
        verify_tokens!(">=", vec![(Category::GreaterEqual, 0, 2)]);
        verify_tokens!("><", vec![(Category::GreaterLess, 0, 2)]);
        verify_tokens!("<", vec![(Category::Less, 0, 1)]);
        verify_tokens!("<<", vec![(Category::LessLess, 0, 2)]);
        verify_tokens!("<=", vec![(Category::LessEqual, 0, 2)]);
        verify_tokens!("-", vec![(Category::Minus, 0, 1)]);
        verify_tokens!("--", vec![(Category::MinusMinus, 0, 2)]);
        verify_tokens!("+", vec![(Category::Plus, 0, 1)]);
        verify_tokens!("+=", vec![(Category::PlusEqual, 0, 2)]);
        verify_tokens!("++", vec![(Category::PlusPlus, 0, 2)]);
        verify_tokens!("/", vec![(Category::Slash, 0, 1)]);
        verify_tokens!("/=", vec![(Category::SlashEqual, 0, 2)]);
        verify_tokens!("*", vec![(Category::Star, 0, 1)]);
        verify_tokens!("**", vec![(Category::StarStar, 0, 2)]);
        verify_tokens!("*=", vec![(Category::StarEqual, 0, 2)]);
    }

    #[test]
    fn triple_tokens() {
        verify_tokens!(">>>", vec![(Category::GreaterGreaterGreater, 0, 3)]);
        verify_tokens!(">>=", vec![(Category::GreaterGreaterEqual, 0, 3)]);
        verify_tokens!(">!<", vec![(Category::GreaterBangLess, 0, 3)]);
        verify_tokens!("<<=", vec![(Category::LessLessEqual, 0, 3)]);
        verify_tokens!("<<<", vec![(Category::LessLessLess, 0, 3)]);
    }

    #[test]
    fn four_tuple_tokens() {
        verify_tokens!("<<<=", vec![(Category::LessLessLessEqual, 0, 4)]);
        verify_tokens!(">>>=", vec![(Category::GreaterGreaterGreaterEqual, 0, 4)]);
    }

    #[test]
    fn unquoteable_string() {
        use StringCategory::*;
        let code = "\"hello I am a closed string\\\"";
        let (tokenizer, result) =
            verify_tokens!(code, vec![(Category::String(Unquoteable), 1, 28)]);
        assert_eq!(
            tokenizer.lookup(result[0].range()),
            "hello I am a closed string\\"
        );
        let code = "\"hello I am a unclosed string\\";
        verify_tokens!(
            code,
            vec![(
                Category::Unclosed(UnclosedCategory::String(Unquoteable)),
                1,
                30
            )]
        );
    }

    #[test]
    fn quoteable_string() {
        use StringCategory::*;
        let code = "'Hello \\'you\\'!'";
        let (tokenizer, result) = verify_tokens!(code, vec![(Category::String(Quoteable), 1, 15)]);
        assert_eq!(tokenizer.lookup(result[0].range()), "Hello \\'you\\'!");

        let code = "'Hello \\'you\\'!\\'";
        verify_tokens!(
            code,
            vec![(
                Category::Unclosed(UnclosedCategory::String(Quoteable)),
                1,
                17
            )]
        );
    }

    #[test]
    fn numbers() {
        use Base::*;
        use Category::*;
        verify_tokens!("0b01", vec![(Number(Binary), 2, 4)]);
        verify_tokens!("1234567890", vec![(Number(Base10), 0, 10)]);
        verify_tokens!("0.123456789", vec![(Number(Base10), 0, 11)]);
        verify_tokens!("012345670", vec![(Number(Octal), 1, 9)]);
        verify_tokens!("0x1234567890ABCDEF", vec![(Number(Hex), 2, 18)]);
        // That would be later illegal because a number if followed by a number
        // but within tokenizing I think it is the best to ignore that and let it be handled by AST
        verify_tokens!("0b02", vec![(Number(Binary), 2, 3), (Number(Base10), 3, 4)]);
        verify_tokens!(
            "0b2",
            vec![(IllegalNumber(Binary), 2, 2), (Number(Base10), 2, 3)]
        );
    }

    #[test]
    fn single_line_comments() {
        use Category::*;
        verify_tokens!(
            "// this is a comment\n;",
            vec![(Comment, 0, 20), (Semicolon, 21, 22)]
        );
    }

    #[test]
    fn multi_line_comments() {
        use Category::*;
        verify_tokens!("/*\n\nthis\nis\na\ncomment\n\n*/", vec![(Comment, 0, 25)]);
        let code = r"
        /*
         * This is very important:
         /*
          * Therefore I do multiple comments inside
          /* comment blocks */
         */
        */
        ";
        verify_tokens!(
            code,
            vec![(Comment, 9, 164)]
        );
        verify_tokens!(
            r"
        /*
         * This is very important:
         /*
          * Therefore I do multiple comments inside
          /* comment blocks but I forgot to close one
         */
        */
        ",
            vec![(Unclosed(UnclosedCategory::Comment), 9, 196)]
        );
    }
}