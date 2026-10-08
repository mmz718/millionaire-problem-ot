import unittest
from unittest.mock import patch
from channel import Channel
from crypto_utils import generate_key, mask
from protocols import (Participant, OriginalAlice, OriginalBob, OTSender, OTReceiver,
                       ProtocolError, compare_original, compare_ot, run_ot,
                       well_spaced, relation_from_bits, validate_wealth)


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ak, cls.bk = generate_key(), generate_key()

    def parties(self, a, b, domain=5):
        return Participant("Alice", a, domain, self.ak), Participant("Bob", b, domain, self.bk)

    def test_exhaustive_domain5(self):
        for a in range(1, 6):
            for b in range(1, 6):
                expected = 2 if a > b else 1 if a == b else 0
                for scheme in (compare_original, compare_ot):
                    with self.subTest(a=a, b=b, scheme=scheme.__name__):
                        self.assertEqual(scheme(*self.parties(a, b)).code, expected)

    def test_repeated_inputs(self):
        for _ in range(3):
            for scheme in (compare_original, compare_ot):
                self.assertEqual(scheme(*self.parties(3, 3)).code, 1)

    def test_singleton_domain(self):
        for scheme in (compare_original, compare_ot):
            self.assertEqual(scheme(*self.parties(1, 1, 1)).code, 1)

    def test_ot_arbitrary_messages_all_choices(self):
        messages = [bytes(range(32)), b"A" * 32, b"B" * 32, b"C" * 32, b"D" * 32]
        for choice in range(1, 6):
            channel = Channel()
            actual = run_ot(OTSender(messages, self.ak), OTReceiver(choice), channel)
            self.assertEqual(actual, messages[choice - 1])
            self.assertEqual(channel.messages, 3)

    def test_circular_spacing(self):
        for values in ([0, 6], [2, 2], [2, 3]):
            self.assertFalse(well_spaced(values, 7))
        self.assertTrue(well_spaced([1, 3, 5], 7))
        self.assertTrue(well_spaced([0], 7))

    def test_modular_request_wrap_and_response_wrap(self):
        sender = OriginalAlice(1, 2, self.ak)
        receiver = OriginalBob(2, 2)
        with patch("protocols.secrets.randbelow", return_value=0):
            request = receiver.request(sender.offer())
        self.assertEqual(int(request["u"], 16), self.ak.public.n - 1)
        response, _ = sender.respond(request)
        self.assertFalse(receiver.finish(response))
        # 直接测试被选中的余数 p-1 在模 p 加 1 后变成 0 的情况。
        receiver._x = 6
        self.assertFalse(receiver.finish({"p": "7", "w": ["3", "0"]}))

    def test_spacing_retry(self):
        sender = OriginalAlice(2, 3, self.ak)
        receiver = OriginalBob(1, 3)
        request = receiver.request(sender.offer())
        with patch("protocols.well_spaced", side_effect=[False, True]):
            response, attempts = sender.respond(request)
        self.assertEqual(attempts, 2)
        self.assertTrue(receiver.finish(response))

    def test_retry_exhaustion(self):
        sender = OriginalAlice(2, 3, self.ak)
        request = OriginalBob(1, 3).request(sender.offer())
        with patch("protocols.well_spaced", return_value=False):
            with self.assertRaises(ProtocolError):
                sender.respond(request, max_attempts=2)

    def test_invalid_wealth(self):
        for value in (0, 6, -1, True, 2.5):
            with self.assertRaises(ValueError):
                validate_wealth(value, 5)

    def test_domain_mismatch(self):
        for scheme in (compare_original, compare_ot):
            with self.assertRaises(ProtocolError):
                scheme(*[Participant("Alice", 1, 3, self.ak), Participant("Bob", 1, 4, self.bk)])

    def test_invalid_ot_choice(self):
        for choice in (0, 4, True):
            with self.assertRaises(ValueError):
                OTReceiver(choice).request(OTSender([b"a", b"b", b"c"], self.ak).offer())

    def test_invalid_messages(self):
        for messages in ([], [b""], [b"a", b"bb"], ["text"]):
            with self.assertRaises(ValueError):
                OTSender(messages, self.ak)

    def test_sender_session_cannot_repeat(self):
        sender = OTSender([b"a", b"b"], self.ak)
        request = OTReceiver(1).request(sender.offer())
        sender.respond(request)
        with self.assertRaises(ProtocolError):
            sender.respond(request)

    def test_receiver_session_cannot_repeat(self):
        receiver = OTReceiver(1)
        offer = OTSender([b"a"], self.ak).offer()
        receiver.request(offer)
        with self.assertRaises(ProtocolError):
            receiver.request(offer)

    def test_session_binding(self):
        sender = OTSender([b"a"], self.ak)
        request = OTReceiver(1).request(sender.offer())
        request["session"] = "00" * 16
        with self.assertRaises(ProtocolError):
            sender.respond(request)

    def test_mask_domain_separation(self):
        pad = mask(b"a" * 16, 1, 42, 256, 32)
        self.assertNotEqual(pad, mask(b"a" * 16, 2, 42, 256, 32))
        self.assertNotEqual(pad, mask(b"b" * 16, 1, 42, 256, 32))

    def test_bytes_are_actual_serialization(self):
        import json
        channel = Channel()
        payload = {"value": "中文"}
        self.assertEqual(channel.send("Alice", "Bob", "test", payload), payload)
        expected = json.dumps({"from": "Alice", "to": "Bob", "kind": "test", "payload": payload},
                              ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.assertEqual(channel.bytes_sent, len(expected))
        self.assertEqual(channel.messages, 1)

    def test_complete_comparison_message_counts(self):
        original = compare_original(*self.parties(5, 1))
        ot = compare_ot(*self.parties(5, 1))
        self.assertEqual(original.messages, 8)
        self.assertEqual(ot.messages, 4)
        self.assertTrue(all("payload" not in entry for entry in original.trace + ot.trace))

    def test_impossible_bits(self):
        with self.assertRaises(ProtocolError):
            relation_from_bits(False, False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
