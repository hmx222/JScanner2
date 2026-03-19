import math
import os
import mmap
import hashlib
from typing import Generator


class SenInfoDiskBloomFilter:
    """
    基于磁盘映射(mmap)的持久化布隆过滤器。
    """

    def __init__(self, filepath: str, capacity: int = 10_000_000, error_rate: float = 0.001):
        self.filepath = filepath
        self.size = int(- (capacity * math.log(error_rate)) / (math.log(2) ** 2))
        self.hash_count = int((self.size / capacity) * math.log(2))
        self.byte_size = (self.size + 7) // 8

        self._ensure_file()

        self.file = open(filepath, "r+b")
        self.mm = mmap.mmap(self.file.fileno(), 0)

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        if not os.path.exists(self.filepath):
            with open(self.filepath, "wb") as f:
                f.write(b'\x00' * self.byte_size)

    def _get_hashes(self, item: str) -> Generator[int, None, None]:
        item_encoded = item.encode("utf8")
        md5 = int(hashlib.md5(item_encoded).hexdigest(), 16)
        sha1 = int(hashlib.sha1(item_encoded).hexdigest(), 16)
        for i in range(self.hash_count):
            yield (md5 + i * sha1) % self.size

    def add(self, item: str) -> bool:
        if self.contains(item): return False
        for pos in self._get_hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            self.mm[byte_index] |= (1 << bit_index)
        return True

    def contains(self, item: str) -> bool:
        for pos in self._get_hashes(item):
            byte_index = pos // 8
            bit_index = pos % 8
            if not (self.mm[byte_index] & (1 << bit_index)):
                return False
        return True

    def close(self):
        if self.mm: self.mm.close()
        if self.file: self.file.close()
