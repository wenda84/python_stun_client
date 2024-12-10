# A STUN Client follow RFC 5389.

import socket
import struct
import random
import hmac
import hashlib
import zlib


# 在这里定义STUN 属性的常量
class STUNAttr:
    USERNAME = 0x0006
    MESSAGE_INTEGRITY = 0x0008
    PRIORITY = 0x0024
    FINGER_PRINT = 0x8028
    ICE_CONTROLLED = 0x8029

class LENGTH:
    STUN_HEAD = 20
    FINGER_PRINT = 8

# 其他可用的公网STUN服务器stun.syncthing.net
def get_stun_ip_port(stun_host, stun_port=3478, user_name=None, password=None, version=2) -> tuple[str, int] | tuple[None, None]:
    '''
    stun_host: STUN服务器地址，测试过的stun服务器有：
        stun.freeswitch.org 
        stun.graftlab.com 
        stun.miwifi.com 
    '''

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    transaction_id = generate_transaction_id()

    if version == 2:
        msg = build_stun_request_v2(transaction_id, user_name, password)
    else:
        msg = build_stun_request(transaction_id)

    try:
        sock.sendto(msg, (stun_host, stun_port))

        data, addr = sock.recvfrom(1024)
    except socket.timeout:
        print("Error: receive STUN response time out.")
        return None, None

    public_address, public_port = parse_stun_response(data, transaction_id)

    sock.close()

    return public_address, public_port


def generate_transaction_id():
    return struct.pack('!III', random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))


def generate_ice_controlled_attribute():
    return struct.pack('!II', random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))


def build_stun_request(transaction_id):
    # 构建 STUN 请求消息
    msg = struct.pack('!HH', 0x0001, 0)
    magic_cookie = 0x2112A442
    msg += struct.pack('!I', magic_cookie)
    msg += transaction_id
    return msg


def parse_stun_response(data, expected_transaction_id):
    # 解析 STUN 响应消息
    if len(data) >= 20 and data[0:2] == b'\x01\x01':
        magic_cookie = struct.unpack('!I', data[4:8])[0]
        if magic_cookie != 0x2112A442:
            print("Error: STUN response received, but magic_cookie does not match.")
            return None, None

        #  校验Transaction ID
        transaction_id = data[8:20]
        if transaction_id != expected_transaction_id:
            print("Error: Received STUN response with unexpected Transaction ID.")
            return None, None

        # 循环解析 TLV 结构中的属性
        pos = 20
        while pos < len(data):
            attribute_type, attribute_length = struct.unpack(
                '!HH', data[pos:pos+4])
            attribute_value = data[pos+4:pos+attribute_length+4]

            if attribute_type == 0x0001:  # MAPPED-ADDRESS attribute
                address_family = struct.unpack('!H', attribute_value[:2])[0]
                if address_family == 0x0001:  # IPv4
                    public_port = struct.unpack('!H', attribute_value[2:4])[0]
                    public_address = socket.inet_ntoa(attribute_value[4:8])
                    return public_address, public_port
            pos += attribute_length + 4  # Move to the next attribute

    return None, None


import struct
import hashlib
import hmac
import zlib

def build_stun_request_v2(transaction_id, user_name: str='aaa:bbb', password: str='ccc:ddd') -> bytes:
    msg = bytearray()

    # 添加 STUN 类型和长度字段
    msg.extend(struct.pack('!HH', 0x0001, 0))

    # 添加 Magic Cookie
    magic_cookie = 0x2112A442
    msg.extend(struct.pack('!I', magic_cookie))

    # 添加 Transaction ID
    msg.extend(transaction_id)

    if user_name and password:
        user_name_bytes = user_name.encode('utf-8')
        msg.extend(struct.pack('!HH', STUNAttr.USERNAME, len(user_name_bytes)))
        msg.extend(user_name_bytes)
        # 补充字节以实现四字节对齐
        padding_length = 4 - (len(user_name_bytes) % 4)
        if padding_length != 4:
            msg.extend(b'\x00' * padding_length)

        # 添加 PRIORITY
        msg.extend(struct.pack('!HHI', STUNAttr.PRIORITY, 4, 1))

        # 添加 ICE_CONTROLLED
        msg.extend(struct.pack('!HH', STUNAttr.ICE_CONTROLLED, 8))
        msg.extend(generate_ice_controlled_attribute())

        # 计算 MESSAGE-INTEGRITY（包括密码）
        user_name_password_bytes = user_name_bytes + password.encode('utf-8')
        hmac_key = hashlib.md5(user_name_password_bytes).digest()
        msg_without_integrity = bytes(msg)  # 这里消息还不包括 MESSAGE-INTEGRITY
        integrity = hmac.new(hmac_key, msg_without_integrity, hashlib.sha1).digest()
        msg.extend(struct.pack('!HH', STUNAttr.MESSAGE_INTEGRITY, 20))
        msg.extend(integrity)

    # 后面要计算FINGER_PRINT，所以【必须】提前计算长度
    struct.pack_into('!H', msg, 2, len(msg) - LENGTH.STUN_HEAD + LENGTH.FINGER_PRINT)

    # 计算 CRC32，与 0x5354554e 进行 XOR 操作
    crc32_value = zlib.crc32(bytes(msg)) & 0xFFFFFFFF
    crc32_xor = crc32_value ^ 0x5354554e

    # 更新 FINGERPRINT 属性
    msg.extend(struct.pack('!HHI', STUNAttr.FINGER_PRINT, 4, crc32_xor))


    return bytes(msg)


if __name__ == '__main__':
    public_address, public_port = get_stun_ip_port(stun_host='stun.freeswitch.org')
    if public_port and public_address:
        print("Your Public Address:", public_address)
