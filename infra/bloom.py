import hashlib
import math
import mmap
import os
from typing import Generator


class DiskBloomFilter:
    """
    基于磁盘映射的持久化布隆过滤器

    使用内存映射文件（mmap）实现布隆过滤器的持久化，支持：
    - 极低内存占用的存在性检查
    - 进程重启后数据不丢失
    - 高效的添加和查询操作

    Attributes:
        filepath: 持久化文件路径
        size: 位数组大小（bit 数）
        hash_count: 哈希函数数量
        byte_size: 位数组对应的字节数
    """

    def __init__(
        self,
        filepath: str,
        capacity: int = 10_000_000,
        error_rate: float = 0.001
    ):
        """
        初始化磁盘布隆过滤器

        Args:
            filepath: 持久化文件路径
            capacity: 预期元素数量（容量）
            error_rate: 期望的误判率（默认 0.1%）
        """
        self.filepath = filepath  # 文件路径
        # 计算位数组大小（根据容量和误判率）
        self.size = int(- (capacity * math.log(error_rate)) / (math.log(2) ** 2))  # 位数组大小(bit)
        # 计算哈希函数数量
        self.hash_count = int((self.size / capacity) * math.log(2))  # 哈希函数数量
        self.byte_size = (self.size + 7) // 8  # 位数组对应字节数

        # 确保目录存在
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # 文件不存在则创建零填充文件
        if not os.path.exists(filepath):
            with open(filepath, "wb") as f:
                f.write(b'\x00' * self.byte_size)

        # 打开文件并创建内存映射
        self.file = open(filepath, "r+b")  # 打开文件句柄
        self.mm = mmap.mmap(self.file.fileno(), 0)  # 创建内存映射

    def _get_hashes(self, item: str) -> Generator[int, None, None]:
        """
        计算元素的多个哈希值（双重哈希法）

        基于 MD5 和 SHA1 生成 hash_count 个不同的哈希值。

        Args:
            item: 待哈希的元素

        Yields:
            int: 哈希值（在位数组中的位置）
        """
        item_encoded = item.encode("utf8")  # 编码为字节流
        md5 = int(hashlib.md5(item_encoded).hexdigest(), 16)  # 计算MD5哈希值
        sha1 = int(hashlib.sha1(item_encoded).hexdigest(), 16)  # 计算SHA1哈希值
        for i in range(self.hash_count):  # 遍历每个哈希函数
            yield (md5 + i * sha1) % self.size

    def add(self, item: str) -> bool:
        """
        添加元素到过滤器中

        Args:
            item: 待添加的元素

        Returns:
            bool: True 表示新增元素，False 表示已存在
        """
        # 如果已存在，返回 False
        if self.contains(item):
            return False
        # 将所有哈希位置对应的位设为 1
        for pos in self._get_hashes(item):  # 遍历所有哈希位置
            byte_index = pos // 8  # 计算字节索引
            bit_index = pos % 8  # 计算位索引
            self.mm[byte_index] |= (1 << bit_index)
        return True

    def contains(self, item: str) -> bool:
        """
        检查元素是否可能存在

        注意：布隆过滤器可能有假阳性（误判存在），但不会有假阴性（不会漏判）。

        Args:
            item: 待检查的元素

        Returns:
            bool: True 表示元素可能存在，False 表示元素肯定不存在
        """
        # 检查所有哈希位置的位是否都为 1
        for pos in self._get_hashes(item):  # 遍历所有哈希位置
            byte_index = pos // 8  # 计算字节索引
            bit_index = pos % 8  # 计算位索引
            if not (self.mm[byte_index] & (1 << bit_index)):
                return False
        return True

    def close(self):
        """
        关闭文件句柄，数据已通过内存映射自动持久化到磁盘

        在关闭前无需手动 flush，mmap 会在同步时自动写回磁盘。
        """
        try:
            self.mm.close()
            self.file.close()
        except Exception:  # 忽略关闭异常
            pass