import re

from app.utils.regex_utils import (
    compile_pattern,
    is_valid_regex,
    match_pattern,
    pattern_matches,
    extract_all_matches,
    sanitize_for_regex,
    build_keyword_pattern,
)


class TestCompilePattern:
    def test_valid_pattern(self):
        pat = compile_pattern(r"\d+")
        assert pat is not None
        assert pat.match("123")

    def test_invalid_pattern(self):
        pat = compile_pattern(r"[invalid")
        assert pat is None

    def test_with_flags(self):
        pat = compile_pattern(r"hello", re.IGNORECASE)
        assert pat is not None
        assert pat.search("HELLO")

    def test_caching(self):
        p1 = compile_pattern(r"\w+")
        p2 = compile_pattern(r"\w+")
        assert p1 is p2


class TestIsValidRegex:
    def test_valid(self):
        assert is_valid_regex(r"\d+") is True

    def test_invalid(self):
        assert is_valid_regex(r"[invalid") is False

    def test_empty_pattern(self):
        assert is_valid_regex("") is True


class TestMatchPattern:
    def test_basic_match(self):
        match = match_pattern(r"error:\s*(.+)", "Error: Connection refused")
        assert match is not None
        assert match.group(1) == "Connection refused"

    def test_no_match(self):
        match = match_pattern(r"\d+", "no digits here")
        assert match is None

    def test_case_insensitive_by_default(self):
        match = match_pattern(r"SELECT", "select * from users")
        assert match is not None

    def test_case_sensitive(self):
        match = match_pattern(r"SELECT", "select * from users", case_sensitive=True)
        assert match is None

    def test_invalid_pattern(self):
        match = match_pattern(r"[invalid", "any text")
        assert match is None


class TestPatternMatches:
    def test_none_pattern_matches_anything(self):
        assert pattern_matches(None, "any text") is True

    def test_none_text_no_match(self):
        assert pattern_matches(r"\d+", None) is False

    def test_match_found(self):
        assert pattern_matches(r"admin", "User: admin@example.com") is True

    def test_no_match(self):
        assert pattern_matches(r"\d{4,}", "abc") is False

    def test_case_insensitive(self):
        assert pattern_matches(r"SELECT", "select") is True

    def test_case_sensitive(self):
        assert pattern_matches(r"SELECT", "select", case_sensitive=True) is False


class TestExtractAllMatches:
    def test_extract_ips(self):
        text = "Server: 192.168.1.1, Gateway: 10.0.0.1"
        results = extract_all_matches(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)
        assert results == ["192.168.1.1", "10.0.0.1"]

    def test_no_matches(self):
        results = extract_all_matches(r"\d+", "no digits")
        assert results == []

    def test_invalid_pattern(self):
        results = extract_all_matches(r"[invalid", "text")
        assert results == []


class TestSanitizeForRegex:
    def test_escapes_dot(self):
        assert sanitize_for_regex("test.txt") == r"test\.txt"

    def test_escapes_special_chars(self):
        assert sanitize_for_regex("foo+bar?baz") == r"foo\+bar\?baz"

    def test_plain_text(self):
        assert sanitize_for_regex("hello") == "hello"


class TestBuildKeywordPattern:
    def test_single_keyword(self):
        pat = build_keyword_pattern(["error"])
        assert pat == r"\b(error)\b"

    def test_multiple_keywords(self):
        pat = build_keyword_pattern(["error", "warning", "fatal"])
        assert pat == r"\b(error|warning|fatal)\b"

    def test_no_word_boundary(self):
        pat = build_keyword_pattern(["admin"], word_boundary=False)
        assert pat == "(admin)"

    def test_empty_list(self):
        assert build_keyword_pattern([]) == ""

    def test_special_chars_escaped(self):
        pat = build_keyword_pattern(["test.v1"])
        assert r"test\.v1" in pat
