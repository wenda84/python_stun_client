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


# 其他可用的公网STUN服务器stun.syncthing.net
def get_stun_ip_info(stun_host='stun.miwifi.com', stun_port=3478, user_name='aaaa:bbbb', password='')->tuple[str, int]|tuple[None, None]:
    # 创建 UDP 套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)  # 设置超时时间

    # 构建 STUN 请求消息
    transaction_id = generate_transaction_id()
    msg = build_stun_request_v2(transaction_id, user_name, password)

    try:
        # 发送 STUN 请求消息到指定的 STUN 服务器
        sock.sendto(msg, (stun_host, stun_port))

        # 接收 STUN 响应消息
        data, addr = sock.recvfrom(1024)
    except socket.timeout:
        return None, None

    # 解析 STUN 响应消息
    public_address, public_port = parse_stun_response(data, transaction_id)

    # 关闭套接字
    sock.close()

    return public_address, public_port


def generate_transaction_id():
    # 生成随机的 Transaction ID
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
            # print("Error: Received STUN response with unexpected Transaction ID.")
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


def build_stun_request_v2(transaction_id, user_name: str, password: str) -> bytes:
    # 构建 STUN 请求消息
    msg = bytearray()

    # 添加 STUN 类型和长度字段
    msg.extend(struct.pack('!HH', 0x0001, 0))

    # 添加 Magic Cookie
    magic_cookie = 0x2112A442
    msg.extend(struct.pack('!I', magic_cookie))

    # 添加 Transaction ID
    msg.extend(transaction_id)

    # 添加用户名
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

    # 计算 MESSAGE-INTEGRITY
    hmac_key = hashlib.md5(user_name_bytes).digest()
    msg_without_integrity = bytes(msg)
    integrity = hmac.new(hmac_key, msg_without_integrity,
                         hashlib.sha1).digest()
    msg.extend(struct.pack('!HH', STUNAttr.MESSAGE_INTEGRITY, 20))
    msg.extend(integrity)

    # 添加 FINGERPRINT
    fingerprint_start = len(msg)
    msg.extend(struct.pack('!HHI', STUNAttr.FINGER_PRINT, 4, 0))
    # 计算 CRC32 校验和
    crc32_value = zlib.crc32(password.encode('utf-8')) & 0xFFFFFFFF
    # 更新 FINGERPRINT 字段的值
    struct.pack_into('!I', msg, fingerprint_start + 4, crc32_value)

    # 更新消息的长度字段
    struct.pack_into('!H', msg, 2, len(msg) - 20)

    return bytes(msg)


if __name__ == '__main__':
    public_address, public_port = get_stun_ip_info()
    if public_port and public_address:
        print("Public Address:", public_address)
