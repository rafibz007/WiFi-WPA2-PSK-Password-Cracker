
def calculate_crc32(data: bytes):
    crc = 0xFFFFFFFF
    polynomial = 0xEDB88320

    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ polynomial
            else:
                crc >>= 1

    crc ^= 0xFFFFFFFF
    return crc.to_bytes(4, 'little')

