# A STUN Client follow RFC 5389.
import socket
import struct
import random
import hmac
import hashlib
import zlib
from typing import Union, Tuple


class STUN_MSG_TYPE:
    BINDING_REQ = 0x0001
    BINDING_SUCC_RSP = 0x0101


class STUN_ATTR_TYPE:
    MAPPED_ADDRESS = 0x0001
    USERNAME = 0x0006
    MESSAGE_INTEGRITY = 0x0008
    XOR_MAPPED_ADDRESS = 0x0020
    PRIORITY = 0x0024
    FINGER_PRINT = 0x8028
    ICE_CONTROLLED = 0x8029
    MAGIC_COOKIE = 0x2112A442


class LENGTH:
    STUN_HEAD = 20
    FINGERPRINT = 8  # total length of TLV


class STATIC_VALUE:
    STUN_MAGIC_COOKIE = 0x2112A442


# 测试过的STUN服务器
TESTED_STUN_SERVERS = ['stun.freeswitch.org', 'stun.graftlab.com', 'stun.miwifi.com', 'stun.kaseya.com']


def get_stun_ip_port(stun_host, stun_port=3478, user_name=None, password=None, version=2) -> Union[Tuple[str, int], Tuple[None, None]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    transaction_id = generate_transaction_id()

    if version == 2:
        msg = build_stun_request(transaction_id, user_name, password)
    else:
        msg = build_stun_request_basic(transaction_id)

    try:
        sock.sendto(msg, (stun_host, stun_port))

        data, addr = sock.recvfrom(1024)
        public_address, public_port = parse_stun_response(data, transaction_id)
        # 如果解析失败
        if public_address is None or public_port is None:
            print("Failed to parse STUN response.")
            return None, None

        return public_address, public_port
    except socket.timeout:
        print(f"Error: receive STUN response from ({stun_host}) time out.")
    except Exception as e:
        print("Error: ", e)
    finally:
        sock.close()

    return None, None


def generate_transaction_id():
    return struct.pack('!III', random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))


def generate_ice_controlled_attribute():
    return struct.pack('!II', random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))


def build_stun_request_basic(transaction_id):
    # 构建 STUN 请求消息
    msg = struct.pack('!HH', 0x0001, 0)
    magic_cookie = STATIC_VALUE.STUN_MAGIC_COOKIE
    msg += struct.pack('!I', magic_cookie)
    msg += transaction_id
    return msg


def build_stun_request(transaction_id, user_name: str, password: str, is_fingerprint: bool = True) -> bytes:
    msg = bytearray()

    # 添加 STUN 类型和长度字段(长度先置0，最后再计算)
    msg.extend(struct.pack('!HH', STUN_MSG_TYPE.BINDING_REQ, 0))

    # 添加 Magic Cookie
    magic_cookie = STATIC_VALUE.STUN_MAGIC_COOKIE
    msg.extend(struct.pack('!I', magic_cookie))

    # 添加 Transaction ID
    msg.extend(transaction_id)

    # PRIORITY, some stun server doesn't support this
    # msg.extend(struct.pack('!HHI', STUNAttr.PRIORITY, 4, 1))

    # ICE_CONTROLLED, not basic STUN ATTR
    # msg.extend(struct.pack('!HH', STUNAttr.ICE_CONTROLLED, 8))
    # msg.extend(generate_ice_controlled_attribute())

    if user_name and password:
        user_name_bytes = user_name.encode('utf-8')
        msg.extend(struct.pack('!HH', STUN_ATTR_TYPE.USERNAME, len(user_name_bytes)))
        msg.extend(user_name_bytes)
        # 补充字节以实现四字节对齐
        padding_length = 4 - (len(user_name_bytes) % 4)
        if padding_length != 4:
            msg.extend(b'\x00' * padding_length)

        # 计算 MESSAGE-INTEGRITY（包括密码）
        user_name_password_bytes = user_name_bytes + password.encode('utf-8')
        hmac_key = hashlib.md5(user_name_password_bytes).digest()
        integrity = hmac.new(hmac_key, msg, hashlib.sha1).digest()
        msg.extend(struct.pack('!HH', STUN_ATTR_TYPE.MESSAGE_INTEGRITY, 20))
        msg.extend(integrity)

    # 增加FINGERPRINT
    if is_fingerprint:
        # 计算FINGER_PRINT时，[必须]提前计算长度，长度需包括FINGER_PRINT。
        struct.pack_into('!H', msg, 2, len(msg) - LENGTH.STUN_HEAD + LENGTH.FINGERPRINT)

        crc32_value = zlib.crc32(bytes(msg)) & 0xFFFFFFFF
        crc32_xor = crc32_value ^ 0x5354554e  # 0x5354554e is defined in RFC 5389
        msg.extend(struct.pack('!HHI', STUN_ATTR_TYPE.FINGER_PRINT, 4, crc32_xor))
    else:
        # 计算长度
        struct.pack_into('!H', msg, 2, len(msg) - LENGTH.STUN_HEAD)

    return bytes(msg)


def parse_stun_response(data:bytes, expected_transaction_id):
    if len(data) < 20:
        print("Error: STUN response is too short.")
        return None, None

    if  struct.unpack('!H', data[0:2])[0] != STUN_MSG_TYPE.BINDING_SUCC_RSP:
        print("Error: STUN response received, but message type is not correct.")
        return None, None

    magic_cookie = struct.unpack('!I', data[4:8])[0]
    if magic_cookie != STATIC_VALUE.STUN_MAGIC_COOKIE:
        print("Error: STUN response received, but magic_cookie does not match.")
        return None, None

    transaction_id = data[8:20]
    if transaction_id != expected_transaction_id:
        print("Error: Received STUN response with unexpected Transaction ID.")
        return None, None

    # 循环解析 TLV 结构中的属性
    pos = 20
    while pos < len(data):
        attribute_type, attribute_length = struct.unpack('!HH', data[pos:pos+4])
        attribute_value = data[pos+4:pos+attribute_length+4]

        if attribute_type == STUN_ATTR_TYPE.MAPPED_ADDRESS:
            address_family = struct.unpack('!H', attribute_value[:2])[0]
            if address_family == 0x0001:  # IPv4
                public_port = struct.unpack('!H', attribute_value[2:4])[0]
                public_address = socket.inet_ntoa(attribute_value[4:8])
                return public_address, public_port
        elif attribute_type == STUN_ATTR_TYPE.XOR_MAPPED_ADDRESS:
            address_family = struct.unpack('!H', attribute_value[:2])[0]
            if address_family == 0x0001:  # IPv4
                # XOR 操作,恢复端口
                xor_public_port = struct.unpack('!H', attribute_value[2:4])[0]
                public_port = xor_public_port ^ STATIC_VALUE.STUN_MAGIC_COOKIE >> 16

                # XOR 操作,恢复 IP 地址
                xor_ip_bytes = attribute_value[4:8]
                public_address_bytes = bytes(
                    [xor_ip_bytes[i] ^ ((STATIC_VALUE.STUN_MAGIC_COOKIE >> (8 * (3-i))) & 0xFF) for i in range(4)]
                )
                public_address = socket.inet_ntoa(public_address_bytes)

                return public_address, public_port
        pos += attribute_length + 4  # Move to the next attribute

    print("Error: STUN response received, Failed to get public IP address and port.")
    return None, None


if __name__ == '__main__':
    get_result = False
    for host in TESTED_STUN_SERVERS:
        public_address, public_port = get_stun_ip_port(stun_host=host)
        if public_port and public_address:
            print(f"Your Public Address:{public_address}, get by {host}")
            get_result = True
            break

    if not get_result:
        print("Can't get your public address")
