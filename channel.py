"""序列化的模拟信道：不携带财富字段，也不记录任何秘密。"""
import json
from dataclasses import dataclass, field


@dataclass
class Channel:
    bytes_sent: int = 0
    messages: int = 0
    summary: list = field(default_factory=list)

    def send(self, sender, receiver, kind, payload):
        envelope = {"from": sender, "to": receiver, "kind": kind, "payload": payload}
        wire = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.bytes_sent += len(wire)
        self.messages += 1
        self.summary.append({"from": sender, "to": receiver, "kind": kind, "bytes": len(wire)})
        # 接收方得到的是反序列化副本，绝不是发送方状态对象的引用。
        return json.loads(wire.decode("utf-8"))["payload"]


def hex_int(value):
    return format(value, "x")


def unhex(value):
    return int(value, 16)
