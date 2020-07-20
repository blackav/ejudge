enum class Token
{
    NO_TOKEN = -1, // special value

    EOF_TOKEN = 0, // EOF marker

    // literals
    SPACE = int(' '),
    CHAR_LITERAL = int('\''),
    INT_LITERAL = int('0'),
    FP_LITERAL = int('1'),
    STRING = int('\"'),
    IDENT = int('I'),

    // operations (1 char)
    NOT = '!',
    PERCENT = '%',
    BITAND = '&',
    LPAREN = '(',
    RPAREN = ')',
    STAR = '*',
    PLUS = '+',
    COMMA = ',',
    MINUS = '-',
    DOT = '.',
    SLASH = '/',
    COLON = ':',
    SEMICOLON = ';',
    LESS = '<',
    EQUAL = '=',
    MORE = '>',
    QUESTION = '?',
    LBRACKET = '[',
    RBRACKET = ']',
    XOR = '^',
    LBRACE = '{',
    BITOR = '|',
    RBRACE = '}',
    COMPL = '~',

    // operations (multichar)
    ADD_ASSIGN = 300, // +=
    AND, // &&
    AND_ASSIGN, // &=
    ARROW, // ->
    ARROWSTAR, // ->* C++
    DECR, // --
    DIV_ASSIGN, // /=
    DOTSTAR, // .* C++
    ELLIPSIS, // ...
    EQ, // ==
    GEQ, // >=
    INCR, // ++
    LEQ, // <=
    LSHIFT, // <<
    LSH_ASSIGN, // <<=
    MUL_ASSIGN, // *=
    MOD_ASSIGN, // %=
    NOT_EQ, // !=
    OR, // ||
    OR_ASSIGN, // |=
    RSHIFT, // >>
    RSH_ASSIGN, // >>=
    SCOPE, // :: C++
    SUB_ASSIGN, // -=
    XOR_ASSIGN, // ^=

    // keywords
    ALIGNAS = 400, // C++11
    ALIGNOF, // C++11
    ASM, // C++
    ATOMIC_CANCEL, // C++??
    ATOMIC_COMMIT, // C++??
    ATOMIC_NOEXCEPT, // C++??
    AUTO,
    BOOL,
    BREAK,
    CASE,
    CATCH, // C++
    CHAR,
    CHAR16_T, // C++11
    CHAR32_T, // C++11
    CLASS, // C++
    COMPLEX,
    CONCEPT, // C++??
    CONST,
    CONSTEXPR, // C++11
    CONST_CAST, // C++
    CONTINUE,
    DECLTYPE, // C++11
    DEFAULT,
    DELETE, // C++
    DO,
    DOUBLE,
    DYNAMIC_CAST, // C++
    ELSE,
    ENUM,
    EXPLICIT, // C++
    EXPORT, // C++
    EXTERN,
    FALSE, // C++
    FLOAT,
    FOR,
    FRIEND, // C++
    GOTO,
    IF,
    IMAGINARY,
    IMPORT, // C++
    INLINE,
    INT,
    LONG,
    MODULE, // C++??
    MUTABLE, // C++
    NAMESPACE, // C++
    NEW, // C++
    NOEXCEPT, // C++11
    NULLPTR, // C++11
    OPERATOR, // C++
    PRIVATE, // C++
    PROTECTED, // C++
    PUBLIC, // C++
    REGISTER,
    REINTERPRET_CAST, // C++
    REQUIRES, // C++??
    RESTRICT,
    RETURN,
    SHORT,
    SIGNED,
    SIZEOF,
    STATIC,
    STATIC_ASSERT, // C++11
    STATIC_CAST, // C++
    STRUCT,
    SWITCH,
    SYNCHRONIZED, // C++??
    TEMPLATE, // C++
    THIS, // C++
    THREAD_LOCAL, // C++11
    THROW, // C++
    TRUE, // C++
    TRY, // C++
    TYPEDEF,
    TYPEID, // C++
    TYPENAME, // C++
    UNION,
    UNSIGNED,
    USING, // C++
    VIRTUAL, // C++
    VOID,
    VOLATILE,
    WCHAR_T, // C++
    WHILE
};
