"""DER / BER 基础解析（本地实现，供 ASN.1、证书、时间戳等模块复用）。"""
from __future__ import annotations

from dataclasses import dataclass, field

from .common import ToolError

# 常用 tag
TAG_NAMES = {
    0x01: "BOOLEAN",
    0x02: "INTEGER",
    0x03: "BIT STRING",
    0x04: "OCTET STRING",
    0x05: "NULL",
    0x06: "OBJECT IDENTIFIER",
    0x07: "ObjectDescriptor",
    0x09: "REAL",
    0x0A: "ENUMERATED",
    0x0B: "EMBEDDED PDV",
    0x0C: "UTF8String",
    0x0D: "RELATIVE-OID",
    0x10: "SEQUENCE",
    0x11: "SET",
    0x12: "NumericString",
    0x13: "PrintableString",
    0x14: "T61String",
    0x15: "VideotexString",
    0x16: "IA5String",
    0x17: "UTCTime",
    0x18: "GeneralizedTime",
    0x19: "GraphicString",
    0x1A: "VisibleString",
    0x1B: "GeneralString",
    0x1C: "UniversalString",
    0x1D: "CHARACTER STRING",
    0x1E: "BMPString",
}

CONSTRUCTED = {0x10, 0x11, 0x1D}


@dataclass
class Node:
    tag: int
    cls: int
    constructed: bool
    length: int
    value: bytes
    header_len: int
    children: list["Node"] = field(default_factory=list)

    @property
    def type_name(self) -> str:
        if self.cls == 0:
            return TAG_NAMES.get(self.tag, f"TAG[{self.tag}]")
        if self.cls == 1:
            return f"[APPLICATION {self.tag}]"
        if self.cls == 2:
            return f"[{self.tag}]"
        return f"[PRIVATE {self.tag}]"

    @property
    def raw(self) -> bytes:
        return bytes([(self.cls << 6) | (0x20 if self.constructed else 0)]) + encode_len(self.length) + self.value


def encode_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def decode_oid(data: bytes) -> str:
    if not data:
        return ""
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _decode_string(tag: int, data: bytes) -> str:
    if tag == 0x1E:
        return data.decode("utf-16-be", "replace")
    if tag == 0x1C:
        return data.decode("utf-32-be", "replace")
    if tag in (0x14, 0x1A, 0x12, 0x13, 0x16, 0x19, 0x1B, 0x15):
        return data.decode("latin-1", "replace")
    return data.decode("utf-8", "replace")


def parse(data: bytes, depth: int = 0) -> Node:
    """解析单个 TLV，返回节点。"""
    if depth > 40:
        raise ToolError("ASN.1 嵌套层数过深")
    if len(data) < 2:
        raise ToolError("ASN.1 数据不完整")
    b0 = data[0]
    cls = b0 >> 6
    constructed = bool(b0 & 0x20)
    tag = b0 & 0x1F
    idx = 1
    if tag == 0x1F:
        tag = 0
        while True:
            if idx >= len(data):
                raise ToolError("ASN.1 标签解析失败")
            b = data[idx]
            idx += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    if idx >= len(data):
        raise ToolError("ASN.1 长度缺失")
    l0 = data[idx]
    idx += 1
    if l0 == 0x80:  # 不定长（BER）
        end = data.find(b"\x00\x00", idx)
        if end < 0:
            raise ToolError("BER 不定长数据缺少结束标记")
        length = end - idx
        header_len = idx
        body = data[idx:end]
    elif l0 & 0x80:
        n = l0 & 0x7F
        if n > 4 or idx + n > len(data):
            raise ToolError("ASN.1 长度字段非法")
        length = int.from_bytes(data[idx:idx + n], "big")
        idx += n
        header_len = idx
        body = data[idx:idx + length]
    else:
        length = l0
        header_len = idx
        body = data[idx:idx + length]
    if len(body) < length:
        raise ToolError("ASN.1 数据长度不足")
    node = Node(tag=tag, cls=cls, constructed=constructed, length=length, value=body, header_len=header_len)
    if constructed:
        off = 0
        while off < len(body):
            child = parse(body[off:], depth + 1)
            node.children.append(child)
            off += child.header_len + child.length
            if child.length == 0 and child.header_len == 0:
                break
    return node


def node_value(node: Node) -> str:
    """节点的人类可读值。"""
    try:
        if node.cls != 0:
            return ""
        if node.tag == 0x06:
            return decode_oid(node.value)
        if node.tag == 0x02:
            return str(int.from_bytes(node.value, "big", signed=True)) if len(node.value) <= 16 else "0x" + node.value.hex()
        if node.tag == 0x01:
            return "TRUE" if node.value and node.value[0] else "FALSE"
        if node.tag == 0x05:
            return "NULL"
        if node.tag == 0x03:
            if not node.value:
                return ""
            unused = node.value[0]
            payload = node.value[1:]
            if unused == 0 and payload and len(payload) <= 64:
                return payload.hex()
            return "0x" + node.value.hex() if len(node.value) <= 32 else f"<{len(node.value)} bytes>"
        if node.tag in (0x0C, 0x13, 0x16, 0x1A, 0x14, 0x1E, 0x1C, 0x12, 0x19):
            return _decode_string(node.tag, node.value)
        if node.tag in (0x17, 0x18):
            return node.value.decode("ascii", "replace")
        if node.tag == 0x04:
            return node.value.hex() if len(node.value) <= 32 else f"<{len(node.value)} bytes>"
        if node.tag == 0x0A:
            return str(int.from_bytes(node.value, "big"))
    except Exception:
        return ""
    return ""


def to_tree(node: Node) -> dict:
    """转换为前端可渲染的树。"""
    value = node_value(node)
    return {
        "type": node.type_name,
        "value": value,
        "contentLength": node.length,
        "hexData": node.value.hex(),
        "children": [to_tree(c) for c in node.children] if node.children else [],
    }


def parse_der(data: bytes) -> Node:
    node = parse(data)
    if node.header_len + node.length < len(data):
        rest = data[node.header_len + node.length:]
        if rest.strip(b"\x00"):
            # 允许多个并列元素：返回第一个，多余部分忽略
            pass
    return node
