"""Offline unit tests for imessage_mcp.py.

Run from the repo root:  /usr/bin/python3 -m unittest discover -s tests -v

No real data is touched: the module's database, Contacts and exclusion paths are
pointed at temporary files before any test runs, and every phone number is from
Ofcom's range reserved for drama (+44 7700 900000–900999).
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import imessage_mcp as m  # noqa: E402  (installs the import guard for this process)

_TMP = tempfile.TemporaryDirectory()
m.DB_PATH = os.path.join(_TMP.name, "missing-chat.db")
m.CONTACT_DBS = []
m.EXCLUDE_FILE = os.path.join(_TMP.name, "excluded_chats.txt")
m.AUDIT_LOG = os.path.join(_TMP.name, "audit.log")
m._CONTACTS = {"7700900001": "Alex Example", "sam@example.com": "Sam Example"}


def typedstream(text):
    """A synthetic attributedBody blob: an NSAttributedString typedstream as the
    Messages app writes it, holding `text`. Mirrors the real header byte for byte."""
    payload = text.encode("utf-8")
    n = len(payload)
    if n < 0x81:
        length = bytes([n])
    elif n <= 0xFFFF:
        length = b"\x81" + n.to_bytes(2, "little")
    else:
        length = b"\x82" + n.to_bytes(3, "little")
    return (b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x12NSAttributedString"
            b"\x00\x84\x84\x08NSObject\x00\x85\x92\x84\x84\x84\x08NSString\x01\x94\x84\x01+"
            + length + payload
            + b"\x86\x84\x02iI\x01" + bytes([min(n, 0x7F)])
            + b"\x92\x84\x84\x84\x0cNSDictionary\x00\x94\x84\x01i\x00\x86\x86")


def write_exclusions(*lines):
    with open(m.EXCLUDE_FILE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


class OTPRedaction(unittest.TestCase):
    def test_verification_code_is_redacted(self):
        self.assertEqual(m.redact("Your verification code is 482913"),
                         "Your verification code is ••••")

    def test_spaced_and_hyphenated_codes_are_redacted(self):
        self.assertNotIn("482", m.redact("Login code: 482 913"))
        self.assertNotIn("4829", m.redact("Your one-time passcode is 4829-13"))

    def test_hint_word_is_case_insensitive(self):
        self.assertEqual(m.redact("OTP 9081"), "OTP ••••")

    def test_ordinary_numbers_without_a_hint_survive(self):
        text = "Table for 4 at 19:30, booking ref 552910"
        self.assertEqual(m.redact(text), text)

    def test_short_numbers_survive_even_with_a_hint(self):
        # 1–3 digit numbers are never codes, so they stay readable.
        self.assertEqual(m.redact("Your code expires in 10 minutes"),
                         "Your code expires in 10 minutes")

    def test_redaction_applies_to_message_bodies(self):
        row = {"text": "Your security code is 771204", "attributedBody": None,
               "cache_has_attachments": 0}
        self.assertEqual(m.body_of(row), "Your security code is ••••")


class Masking(unittest.TestCase):
    def test_international_number_is_masked(self):
        self.assertEqual(m.mask("+447700900123"), "+44 •••• •••123")

    def test_national_number_is_masked(self):
        self.assertEqual(m.mask("07700 900123"), "0 •••• •••123")

    def test_email_keeps_only_first_letter_and_domain(self):
        self.assertEqual(m.mask("jordan@example.com"), "j•••@example.com")

    def test_alphanumeric_sender_ids_are_shown(self):
        self.assertEqual(m.mask("ExampleBank"), "ExampleBank")
        self.assertEqual(m.mask("80800"), "80800")      # short code: a business, not a person

    def test_known_contact_shows_name_whatever_the_prefix(self):
        for handle in ("+447700900001", "07700900001", "+44 7700 900001"):
            self.assertEqual(m.name_for(handle), "Alex Example", handle)

    def test_known_email_contact_shows_name(self):
        self.assertEqual(m.name_for("Sam@Example.com"), "Sam Example")

    def test_unknown_number_never_appears_in_full(self):
        out = m.name_for("+447700900999")
        self.assertNotIn("7700900999", m.digits(out))
        self.assertTrue(out.endswith("999"))


class Exclusions(unittest.TestCase):
    CHATS = {
        1: {"id": 1, "name": "Alex Example", "group": False, "archived": False,
            "handles": ["+447700900001", "+447700900001"]},
        2: {"id": 2, "name": "Book Club", "group": True, "archived": False,
            "handles": ["+447700900002", "+447700900003", "chat123"]},
        3: {"id": 3, "name": "j•••@example.com", "group": False, "archived": False,
            "handles": ["jordan@example.com", "jordan@example.com"]},
        4: {"id": 4, "name": "ExampleBank", "group": False, "archived": False,
            "handles": ["ExampleBank", "ExampleBank"]},
    }

    def tearDown(self):
        if os.path.exists(m.EXCLUDE_FILE):
            os.remove(m.EXCLUDE_FILE)

    def test_no_file_excludes_nothing(self):
        self.assertEqual(m.excluded_ids(self.CHATS), set())

    def test_comments_and_blank_lines_are_ignored(self):
        write_exclusions("# Alex Example", "", "   ")
        self.assertEqual(m.excluded_ids(self.CHATS), set())

    def test_name_match_is_case_insensitive_substring(self):
        write_exclusions("book")
        self.assertEqual(m.excluded_ids(self.CHATS), {2})

    def test_id_rule(self):
        write_exclusions("id:4", "id:not-a-number")
        self.assertEqual(m.excluded_ids(self.CHATS), {4})

    def test_number_matches_in_any_format(self):
        write_exclusions("07700 900003")             # a member of the group chat
        self.assertEqual(m.excluded_ids(self.CHATS), {2})

    def test_email_handle_rule(self):
        write_exclusions("Jordan@Example.com")
        self.assertEqual(m.excluded_ids(self.CHATS), {3})

    def test_excluded_chat_cannot_be_resolved(self):
        write_exclusions("Alex")
        excl = m.excluded_ids(self.CHATS)
        for ref in ("Alex Example", "id:1", "1"):
            chat, err = m.resolve_chat(self.CHATS, ref, excl)
            self.assertIsNone(chat, ref)
            self.assertIn("No readable chat", err)


class AttributedBodyDecoder(unittest.TestCase):
    def test_short_string(self):
        self.assertEqual(m.decode_attributed(typedstream("See you at 7?")), "See you at 7?")

    def test_unicode(self):
        text = "Café on Saturday? 🎉 — é, ü, 日本"
        self.assertEqual(m.decode_attributed(typedstream(text)), text)

    def test_two_byte_length(self):
        text = "long message " * 40                    # > 0x80 bytes: 0x81 length prefix
        self.assertEqual(m.decode_attributed(typedstream(text)), text)

    def test_three_byte_length(self):
        text = "x" * 70000                             # > 0xFFFF bytes: 0x82 length prefix
        self.assertEqual(m.decode_attributed(typedstream(text)), text)

    def test_empty_or_unrecognised_blobs_return_none(self):
        for blob in (None, b"", b"not a typedstream", b"NSString with no payload marker"):
            self.assertIsNone(m.decode_attributed(blob), blob)

    def test_body_falls_back_to_attributed_body_and_strips_placeholder(self):
        row = {"text": None, "attributedBody": typedstream("￼Look at this"),
               "cache_has_attachments": 1}
        self.assertEqual(m.body_of(row), "[📎 attachment] Look at this")


class NetworkGuard(unittest.TestCase):
    def test_network_and_process_modules_are_blocked(self):
        for name in ("socket", "ssl", "urllib.request", "http.client", "smtplib",
                     "asyncio", "subprocess", "requests"):
            with self.assertRaises(ImportError, msg=name):
                __import__(name)

    def test_import_statement_is_blocked_even_if_already_loaded(self):
        with self.assertRaises(ImportError):
            import socket  # noqa: F401

    def test_harmless_modules_still_import(self):
        import json, re  # noqa: E401,F401


class SyntheticDatabase(unittest.TestCase):
    """End to end against a tiny chat.db with the columns the server reads."""

    @classmethod
    def setUpClass(cls):
        cls.path = os.path.join(_TMP.name, "chat.db")
        con = sqlite3.connect(cls.path)
        con.executescript("""
            CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
            CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, chat_identifier TEXT, display_name TEXT,
                               style INTEGER, is_archived INTEGER);
            CREATE TABLE chat_handle_join (chat_id INTEGER, handle_id INTEGER);
            CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, attributedBody BLOB,
                                  is_from_me INTEGER, is_read INTEGER, date INTEGER,
                                  cache_has_attachments INTEGER, service TEXT, handle_id INTEGER,
                                  item_type INTEGER, associated_message_type INTEGER);
            CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
            INSERT INTO handle VALUES (1, '+447700900001'), (2, '+447700900777');
            INSERT INTO chat VALUES (1, '+447700900001', '', 45, 0), (2, '+447700900777', '', 45, 0);
            INSERT INTO chat_handle_join VALUES (1, 1), (2, 2);
        """)
        base = 800_000_000 * 10**9                     # 2026, in Apple-epoch nanoseconds
        rows = [
            (1, "Picnic on Sunday?", None, 0, 1),
            (2, None, typedstream("Sunday works, bring the blanket"), 1, 1),
            (3, None, typedstream("Your verification code is 552871"), 0, 2),
            (4, None, typedstream("Picnic is cancelled, sorry"), 0, 2),
        ]
        for rowid, text, blob, mine, chat in rows:
            con.execute("INSERT INTO message VALUES (?,?,?,?,1,?,0,'iMessage',?,0,0)",
                        (rowid, text, blob, mine, base + rowid * 10**9, chat))
            con.execute("INSERT INTO chat_message_join VALUES (?,?)", (chat, rowid))
        con.commit()
        con.close()
        cls.saved = m.DB_PATH
        m.DB_PATH = cls.path

    @classmethod
    def tearDownClass(cls):
        m.DB_PATH = cls.saved

    def tearDown(self):
        if os.path.exists(m.EXCLUDE_FILE):
            os.remove(m.EXCLUDE_FILE)

    def test_connection_refuses_writes(self):
        con = m.connect()
        with self.assertRaises(sqlite3.OperationalError):
            con.execute("DELETE FROM message")

    def test_search_finds_text_held_only_in_attributed_body(self):
        out = m.tool_search({"query": "blanket"})
        self.assertIn("Sunday works, bring the blanket", out)
        self.assertTrue(out.startswith(m.UNTRUSTED))

    def test_search_spans_both_storage_forms(self):
        out = m.tool_search({"query": "picnic"})
        self.assertIn("2 message(s)", out)

    def test_output_masks_unknown_numbers_and_redacts_codes(self):
        out = m.tool_read_chat({"chat": "id:2"})
        self.assertNotIn("7700900777", out.replace(" ", ""))
        self.assertNotIn("552871", out)
        self.assertIn("+44 •••• •••777", out)

    def test_excluded_chat_is_invisible_to_search(self):
        write_exclusions("+447700900777")
        self.assertEqual(m.tool_search({"query": "picnic"}).count("Picnic"), 1)
        self.assertIn("No readable chat", m.tool_read_chat({"chat": "id:2"}))

    def test_audit_log_never_contains_message_text(self):
        m.tool_search({"query": "blanket"})
        with open(m.AUDIT_LOG, encoding="utf-8") as fh:
            log = fh.read()
        self.assertIn("search", log)
        self.assertNotIn("bring the", log)


if __name__ == "__main__":
    unittest.main()
