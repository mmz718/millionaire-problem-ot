"""RSA 置换与显式编码的哈希掩码。"""
from dataclasses import dataclass
import hashlib
import math
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    @property
    def width(self):
        return (self.n.bit_length() + 7) // 8

    def apply(self, value):
        return pow(value % self.n, self.e, self.n)


@dataclass(frozen=True)
class PrivateKey:
    public: PublicKey
    d: int

    def invert(self, value):
        # 让两套方案使用同一个模幂实现，便于公平对比。
        return pow(value % self.public.n, self.d, self.public.n)


def generate_key(bits=2048):
    if bits < 2048 or bits % 256:
        raise ValueError("RSA bits must be a multiple of 256 and at least 2048")
    numbers = rsa.generate_private_key(public_exponent=65537, key_size=bits).private_numbers()
    return PrivateKey(PublicKey(numbers.public_numbers.n, numbers.public_numbers.e), numbers.d)


def random_prime(bits):
    """生成新的半模数长度素数，借助 cryptography 调用 OpenSSL。

    只取用其中的 p；辅助 RSA 密钥被丢弃，既不发送也不保留。
    这样可以避免在 Python 中再实现一套概率素性检验。
    """
    if bits < 512 or bits % 128:
        raise ValueError("prime bits must be a multiple of 128 and at least 512")
    numbers = rsa.generate_private_key(public_exponent=65537, key_size=bits * 2).private_numbers()
    return numbers.p


def sample_unit(n):
    while True:
        value = secrets.randbelow(n - 1) + 1
        if math.gcd(value, n) == 1:
            return value


def mask(session, index, root, width, length):
    """SHAKE256 随机预言机式掩码；每个字段都采用固定编码。"""
    data = b"HW2-RSA-OT-v1\0" + session + index.to_bytes(4, "big") + root.to_bytes(width, "big")
    return hashlib.shake_256(data).digest(length)


def xor_bytes(left, right):
    if len(left) != len(right):
        raise ValueError("mask length mismatch")
    return bytes(a ^ b for a, b in zip(left, right))
