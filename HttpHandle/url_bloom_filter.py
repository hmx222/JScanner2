from pybloom_live import ScalableBloomFilter


class URLBloomFilter:
    """
    爬虫URL去重专用布隆过滤器工具类
    基于可扩展布隆过滤器实现，支持动态数据量适应
    """

    def __init__(self,
                 initial_capacity: int = 10000,
                 error_rate: float = 0.001,
                 mode: int = 4):
        """
        初始化布隆过滤器

        :param initial_capacity: 初始容量，根据预期最小数据量设置
        :param error_rate: 允许的误判率（0~1之间），值越小占用空间越大
        :param mode: 扩展模式，LARGE（4倍扩展）适合大数据量，SMALL（2倍扩展）适合中小数据量
        """
        self.bloom = ScalableBloomFilter(
            initial_capacity=initial_capacity,
            error_rate=error_rate,
            mode=mode
        )
        self.initial_capacity = initial_capacity
        self.error_rate = error_rate

    def is_processed(self, url: str) -> bool:
        """
        检查URL是否可能已被处理

        :param url: 待检查的URL
        :return: True（可能已处理）/ False（一定未处理）
        """
        if not isinstance(url, str):
            raise TypeError("URL必须是字符串类型")
        return url in self.bloom

    def mark_as_processed(self, url: str) -> None:
        """
        标记URL为已处理（添加到布隆过滤器）

        :param url: 待标记的URL
        """
        if not isinstance(url, str):
            raise TypeError("URL必须是字符串类型")
        self.bloom.add(url)

    def batch_mark_processed(self, urls: list[str]) -> None:
        """
        批量标记URL为已处理

        :param urls: URL列表
        """
        for url in urls:
            self.mark_as_processed(url)

    def __str__(self) -> str:
        """返回过滤器状态描述"""
        return (f"URLBloomFilter(初始容量={self.initial_capacity}, "
                f"误判率={self.error_rate}, 当前元素数≈{len(self.bloom)})")
