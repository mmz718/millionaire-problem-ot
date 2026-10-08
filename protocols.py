"""两方状态机；协调器只转发消息，绝不直接比较双方输入。"""
from dataclasses import dataclass
import secrets
import time
from channel import Channel, hex_int, unhex
from crypto_utils import PublicKey, mask, random_prime, sample_unit, xor_bytes

BOB_RICHER, EQUAL, ALICE_RICHER = 0, 1, 2
LABELS = {BOB_RICHER: "Bob 更富有", EQUAL: "双方财富相等", ALICE_RICHER: "Alice 更富有"}


class ProtocolError(RuntimeError):
    pass


def validate_wealth(value, domain):
    if type(domain) is not int or not 1 <= domain <= 10000:
        raise ValueError("domain must be an integer in [1, 10000]")
    if type(value) is not int or not 1 <= value <= domain:
        raise ValueError("wealth must be an integer in the public domain")


def well_spaced(values, p):
    """模 p 圆环间距检查；拒绝重复、相邻以及首尾环绕相邻的情况。"""
    ordered = sorted(values)
    if len(ordered) <= 1:
        return True
    return all(right - left >= 2 for left, right in zip(ordered, ordered[1:])) and p - ordered[-1] + ordered[0] >= 2


class OriginalAlice:
    def __init__(self, wealth, domain, key, name="Alice"):
        validate_wealth(wealth, domain)
        self._wealth, self.domain, self._key, self.name = wealth, domain, key, name

    def offer(self):
        return {"n": hex_int(self._key.public.n), "e": self._key.public.e, "domain": self.domain}

    def respond(self, request, max_attempts=32, prime_factory=random_prime):
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        n = self._key.public.n
        u = unhex(request["u"])
        if not 0 <= u < n:
            raise ProtocolError("invalid original request")
        ys = [self._key.invert((u + i - 1) % n) for i in range(1, self.domain + 1)]
        for attempt in range(1, max_attempts + 1):
            p = prime_factory(n.bit_length() // 2)
            zs = [y % p for y in ys]
            if well_spaced(zs, p):
                ws = [(z + int(i > self._wealth)) % p for i, z in enumerate(zs, 1)]
                return {"p": hex_int(p), "w": [hex_int(w) for w in ws]}, attempt
        raise ProtocolError("prime spacing retries exhausted; no result released")


class OriginalBob:
    def __init__(self, wealth, domain, name="Bob"):
        validate_wealth(wealth, domain)
        self._wealth, self.domain, self.name = wealth, domain, name

    def request(self, offer):
        if offer["domain"] != self.domain:
            raise ProtocolError("domain mismatch")
        public = PublicKey(unhex(offer["n"]), offer["e"])
        # 在完整 RSA 环上均匀取值：无论 b 是多少，平移后的请求 u 都保持均匀。
        self._x = secrets.randbelow(public.n)
        return {"u": hex_int((public.apply(self._x) - self._wealth + 1) % public.n)}

    def finish(self, response):
        p = unhex(response["p"])
        ws = [unhex(w) for w in response["w"]]
        if p <= 2 or len(ws) != self.domain or any(not 0 <= w < p for w in ws):
            raise ProtocolError("invalid original response")
        return ws[self._wealth - 1] == self._x % p


class OTSender:
    def __init__(self, messages, key):
        if not messages or len(messages) > 10000 or any(type(m) is not bytes for m in messages):
            raise ValueError("OT needs 1..10000 byte messages")
        if len({len(m) for m in messages}) != 1 or len(messages[0]) == 0:
            raise ValueError("OT messages must have the same positive length")
        self._messages, self._key = tuple(messages), key
        self._session = secrets.token_bytes(16)
        self._used = False
        n = key.public.n
        if len(messages) >= n:
            raise ValueError("too many messages for modulus")
        offsets = set()
        self._offsets = []
        while len(self._offsets) < len(messages):
            value = secrets.randbelow(n)
            if value not in offsets:
                offsets.add(value)
                self._offsets.append(value)

    def offer(self):
        return {"n": hex_int(self._key.public.n), "e": self._key.public.e,
                "offsets": [hex_int(s) for s in self._offsets],
                "session": self._session.hex(), "length": len(self._messages[0])}

    def respond(self, request):
        if self._used:
            raise ProtocolError("OT sender session cannot be reused")
        v = unhex(request["v"])
        if request["session"] != self._session.hex() or not 0 <= v < self._key.public.n:
            raise ProtocolError("invalid OT request")
        self._used = True
        ciphertexts = []
        for index, (offset, message) in enumerate(zip(self._offsets, self._messages), 1):
            root = self._key.invert((v - offset) % self._key.public.n)
            ciphertexts.append(xor_bytes(message, mask(self._session, index, root, self._key.public.width, len(message))).hex())
        return {"session": self._session.hex(), "ciphertexts": ciphertexts}


class OTReceiver:
    def __init__(self, choice):
        self._choice = choice
        self._used = False

    def request(self, offer):
        if self._used:
            raise ProtocolError("OT receiver session cannot be reused")
        self._used = True
        public = PublicKey(unhex(offer["n"]), offer["e"])
        offsets = [unhex(s) for s in offer["offsets"]]
        if type(self._choice) is not int or not 1 <= self._choice <= len(offsets):
            raise ValueError("invalid OT choice")
        if len(set(offsets)) != len(offsets) or any(not 0 <= s < public.n for s in offsets):
            raise ProtocolError("invalid OT offsets")
        self._session = bytes.fromhex(offer["session"])
        if len(self._session) != 16 or type(offer["length"]) is not int or offer["length"] < 1:
            raise ProtocolError("invalid OT offer")
        self._length, self._count, self._public = offer["length"], len(offsets), public
        self._k = sample_unit(public.n)
        v = (offsets[self._choice - 1] + public.apply(self._k)) % public.n
        return {"session": self._session.hex(), "v": hex_int(v)}

    def finish(self, response):
        if response["session"] != self._session.hex() or len(response["ciphertexts"]) != self._count:
            raise ProtocolError("invalid OT response")
        ciphertexts = [bytes.fromhex(c) for c in response["ciphertexts"]]
        if any(len(c) != self._length for c in ciphertexts):
            raise ProtocolError("invalid OT ciphertext length")
        pad = mask(self._session, self._choice, self._k, self._public.width, self._length)
        return xor_bytes(ciphertexts[self._choice - 1], pad)


class Participant:
    """参与方仅使用自己的秘密来构造对应角色的状态。"""
    def __init__(self, name, wealth, domain, key):
        validate_wealth(wealth, domain)
        self.name, self.domain, self._wealth, self._key = name, domain, wealth, key

    def original_sender(self):
        return OriginalAlice(self._wealth, self.domain, self._key, self.name)

    def original_receiver(self):
        return OriginalBob(self._wealth, self.domain, self.name)

    def comparison_sender(self):
        messages = [bytes([ALICE_RICHER if self._wealth > i else EQUAL if self._wealth == i else BOB_RICHER])
                    for i in range(1, self.domain + 1)]
        return OTSender(messages, self._key)

    def comparison_receiver(self):
        return OTReceiver(self._wealth)


@dataclass
class RunResult:
    code: int
    elapsed_ms: float
    bytes_sent: int
    messages: int
    prime_attempts: int
    trace: list


def original_phase(sender, receiver, channel, **options):
    offer = channel.send(sender.name, receiver.name, "original_public", sender.offer())
    request = channel.send(receiver.name, sender.name, "original_request", receiver.request(offer))
    response, attempts = sender.respond(request, **options)
    response = channel.send(sender.name, receiver.name, "original_response", response)
    bit = receiver.finish(response)
    result = channel.send(receiver.name, sender.name, "original_bit", {"ge": bit})
    return result["ge"], attempts


def relation_from_bits(first, second):
    if first and second:
        return EQUAL
    if first:
        return ALICE_RICHER
    if second:
        return BOB_RICHER
    raise ProtocolError("inconsistent comparison bits")


def compare_original(alice, bob, **options):
    if alice.domain != bob.domain:
        raise ProtocolError("domain mismatch")
    channel = Channel()
    start = time.perf_counter_ns()
    first, tries1 = original_phase(alice.original_sender(), bob.original_receiver(), channel, **options)
    second, tries2 = original_phase(bob.original_sender(), alice.original_receiver(), channel, **options)
    code = relation_from_bits(first, second)
    elapsed = (time.perf_counter_ns() - start) / 1e6
    return RunResult(code, elapsed, channel.bytes_sent, channel.messages, tries1 + tries2, channel.summary)


def run_ot(sender, receiver, channel):
    offer = channel.send("Alice", "Bob", "ot_public", sender.offer())
    request = channel.send("Bob", "Alice", "ot_request", receiver.request(offer))
    response = channel.send("Alice", "Bob", "ot_response", sender.respond(request))
    return receiver.finish(response)


def compare_ot(alice, bob):
    if alice.domain != bob.domain:
        raise ProtocolError("domain mismatch")
    channel = Channel()
    start = time.perf_counter_ns()
    selected = run_ot(alice.comparison_sender(), bob.comparison_receiver(), channel)
    if len(selected) != 1 or selected[0] not in LABELS:
        raise ProtocolError("invalid comparison result")
    result = channel.send("Bob", "Alice", "comparison_result", {"code": selected[0]})
    elapsed = (time.perf_counter_ns() - start) / 1e6
    return RunResult(result["code"], elapsed, channel.bytes_sent, channel.messages, 0, channel.summary)
