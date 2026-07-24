import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

import json_repair
from openai import OpenAI, APIConnectionError, APIStatusError, RateLimitError, APITimeoutError

from config.config import BASE_URL, API_KEY

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "config/models_config.json"


@dataclass
class ModelStatus:
    """
    模型状态跟踪器

    记录每个 AI 模型的健康状态，支持故障转移和冷却机制。
    当模型连续出错时，冷却时间会指数增长。
    """
    model_name: str
    is_available: bool = True
    cooldown_until: float = 0.0
    error_count: int = 0
    COOLDOWN_BASE = 30      # 基础冷却时间（秒）
    MAX_COOLDOWN = 600      # 最大冷却时间（秒，10分钟）

    def get_cooldown_time(self) -> int:
        """
        计算本次冷却时间（指数退避）

        Returns:
            int: 冷却时间（秒）
        """
        return min(self.error_count * self.COOLDOWN_BASE, self.MAX_COOLDOWN)

    def mark_error(self, error_msg: str):
        """
        标记模型错误，增加错误计数并进入冷却

        Args:
            error_msg: 错误描述
        """
        self.error_count += 1
        cooldown_seconds = self.get_cooldown_time()
        self.cooldown_until = time.time() + cooldown_seconds
        self.is_available = False
        logger.warning(
            f"❌ 模型 [{self.model_name}] 发生错误({error_msg}) -> 进入冷却 | "
            f"错误次数：{self.error_count} | 冷却时间：{cooldown_seconds}秒"
        )

    def mark_success(self):
        """标记模型成功，重置错误计数"""
        if self.error_count > 0:
            logger.info(f"✅ 模型 [{self.model_name}] 恢复正常，重置错误计数")
        self.error_count = 0
        self.is_available = True
        self.cooldown_until = 0.0

    def check_and_restore(self) -> bool:
        """
        检查冷却是否到期，如果到期则恢复模型可用状态

        Returns:
            bool: 是否刚刚恢复（冷却到期）
        """
        if not self.is_available and time.time() >= self.cooldown_until:
            self.is_available = True
            self.cooldown_until = 0.0
            logger.info(f"🔄 模型 [{self.model_name}] 冷却到期，重新投入池中")
            return True
        return False


class ConfigWatcher(threading.Thread):
    """
    模型配置文件监控器（后台线程）

    定期检查 models_config.json 文件的修改时间，
    若有变化则自动热更新模型列表。
    """

    def __init__(self, file_path: str, client_ref: 'AIHubClient', interval: int = 30):
        """
        初始化配置监控器

        Args:
            file_path: 配置文件路径
            client_ref: AIHubClient 实例引用（用于更新模型列表）
            interval: 检查间隔（秒）
        """
        super().__init__(daemon=True)
        self.file_path = file_path
        self.client_ref = client_ref
        self.interval = interval
        self.running = True
        try:
            self.last_modified = os.path.getmtime(file_path)
        except FileNotFoundError:
            self.last_modified = 0

    def run(self):
        """后台线程主循环：定期检查文件变化"""
        while self.running:
            try:
                time.sleep(self.interval)
                if os.path.exists(self.file_path):
                    current_mtime = os.path.getmtime(self.file_path)
                    if current_mtime != self.last_modified:
                        self.last_modified = current_mtime
                        self._reload_models()
            except Exception as e:
                logger.error(f"ConfigWatcher 监控异常：{e}")

    def _reload_models(self):
        """
        重新加载模型配置

        读取配置文件中的模型列表，更新 AIHubClient 的模型池。
        """
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            new_models = config.get('models', [])
            if not new_models:
                return
            # 线程安全地更新模型列表和状态
            with self.client_ref._lock:
                self.client_ref._models = new_models
                self.client_ref._model_statuses = [ModelStatus(model_name=m) for m in new_models]
            logger.info(f"📥 模型配置热更新成功 | 普通模型: {new_models}")
        except Exception as e:
            logger.error(f"配置加载失败：{e}")

    def stop(self):
        """停止监控线程"""
        self.running = False


class AIHubClient:
    """
    AI 模型客户端（支持多模型故障转移）

    维护一个 AI 模型池，自动在模型间切换和冷却管理。
    支持模型配置热更新、JSON 响应修复、请求重试等功能。
    """

    def __init__(self, api_key: str, base_url: str, models: List[str] = None,
                 config_file: str = None, timeout: int = 180):
        """
        初始化 AI 客户端

        Args:
            api_key: API 密钥
            base_url: API 基础地址
            models: 初始模型列表
            config_file: 模型配置文件路径（用于热更新）
            timeout: 请求超时时间（秒）
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self._config_file = config_file
        # 初始化 OpenAI SDK 客户端
        self._client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=timeout,
            max_retries=0  # 禁用 SDK 内置重试，使用自定义重试逻辑
        )

        # 加载初始模型列表
        if not models and config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                models = config.get('models', [])
            except Exception as e:
                logger.warning(f"配置文件读取失败：{e}")
        else:
            pass

        self._models = models or []
        # 为每个模型创建状态跟踪器
        self._model_statuses = [ModelStatus(model_name=m) for m in self._models]
        self._lock = threading.Lock()

        # 启动配置监控器（热更新模型列表）
        if config_file:
            self._config_watcher = ConfigWatcher(config_file, self, interval=30)
            self._config_watcher.start()

        logger.info(f"🚀 AIHubClient (SDK版) 初始化完成 | 代理模型数：{len(self._models)}")

    def _get_available_model(self) -> Optional[ModelStatus]:
        """
        获取当前可用的模型（线程安全）

        先尝试恢复已冷却到期的模型，再返回第一个可用模型。

        Returns:
            Optional[ModelStatus]: 可用模型的状态对象，无可用模型返回 None
        """
        with self._lock:
            # 检查并恢复冷却到期的模型
            for status in self._model_statuses:
                status.check_and_restore()
            # 返回第一个可用模型
            for status in self._model_statuses:
                if status.is_available:
                    return status
            return None

    def _clean_content(self, text: str) -> str:
        """
        清理 AI 返回内容

        剔除所有深度思考标签（如 <think>...</think>）和 Markdown 代码块标记。

        Args:
            text: AI 原始返回文本

        Returns:
            str: 清理后的文本
        """
        if not text: return ""
        # 剔除 <think>...</think> 标签
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)
        # 剔除 Markdown 代码块标记（方便直接解析内容）
        text = re.sub(r'```json\s*|```', '', text).strip()
        return text

    def chat(self, messages: list, require_json: bool = False, **kwargs) -> any:
        """
        向 AI 模型发送聊天请求（含自动故障转移）

        遍历模型池，逐个尝试直到成功或全部失败。
        支持 JSON 模式输出、错误重试和模型冷却管理。

        Args:
            messages: OpenAI 格式的消息列表
            require_json: 是否要求 JSON 格式输出
            **kwargs: 额外参数（如 max_tokens, temperature 等）

        Returns:
            any: AI 返回的内容。require_json=True 时返回解析后的 JSON 对象；
                 否则返回字符串。全部模型失败时返回空字典或错误信息。
        """
        extra_body = kwargs.pop("extra_body", {})
        extra_body["enable_thinking"] = False

        if require_json:
            kwargs["response_format"] = {"type": "json_object"}

        retry_history = []
        max_attempts = len(self._model_statuses)

        for attempt_num in range(max_attempts):
            model_status = self._get_available_model()
            if not model_status:
                logger.error(f"❌ 所有 {max_attempts} 个模型均不可用，停止重试")
                break

            curr_model = model_status.model_name
            logger.info(f"🔄 尝试模型 [{curr_model}] (第 {attempt_num + 1}/{max_attempts} 次)")

            try:
                # 调用 OpenAI API
                response = self._client.chat.completions.create(
                    model=curr_model,
                    messages=messages,
                    extra_body=extra_body,
                    **kwargs
                )

                raw_text = response.choices[0].message.content
                if not raw_text:
                    logger.warning(f"⚠️ 模型 [{curr_model}] 返回空内容")
                    raise ValueError("Empty Response")

                # 标记模型成功
                model_status.mark_success()
                final_text = self._clean_content(raw_text)

                # JSON 模式：尝试解析并修复
                if require_json:
                    obj = json_repair.repair_json(final_text, return_objects=True)
                    if isinstance(obj, (dict, list)):
                        logger.info(f"✅ 模型 [{curr_model}] 成功返回 JSON")
                        return obj
                    raise ValueError("JSON Repair Failed")

                logger.info(f"✅ 模型 [{curr_model}] 成功返回")
                return final_text

            except (APIConnectionError, APITimeoutError, RateLimitError) as e:
                # 网络级错误：连接失败、超时、速率限制
                model_status.mark_error(f"Network/Limit: {type(e).__name__}")
                retry_history.append(f"{curr_model}(Error)")
                logger.warning(f"⚠️ 模型 [{curr_model}] 网络错误，准备切换: {e}")

            except APIStatusError as e:
                # API 级错误：根据状态码处理
                if e.status_code >= 500:
                    model_status.mark_error(f"Server Error: {e.status_code}")
                    retry_history.append(f"{curr_model}({e.status_code})")
                    logger.warning(f"⚠️ 模型 [{curr_model}] 服务器错误 {e.status_code}，准备切换")
                elif e.status_code == 402:
                    model_status.mark_error(f"Payment Required: {e.status_code}")
                    retry_history.append(f"{curr_model}(402)")
                    logger.warning(f"💰 模型 [{curr_model}] 余额不足 (402)，准备切换到下一个模型")
                else:
                    model_status.mark_error(f"Client Error: {e.status_code}")
                    retry_history.append(f"{curr_model}({e.status_code})")
                    logger.warning(f"⚠️ 模型 [{curr_model}] 客户端错误 {e.status_code}，准备切换")

            except Exception as e:
                # 其他异常（包括空响应）
                error_msg = str(e)
                if "Empty Response" in error_msg:
                    logger.warning(f"⚠️ 模型 [{curr_model}] 返回空响应，可能是模型限制或配置问题")
                model_status.mark_error(f"Logic Error: {error_msg}")
                retry_history.append(f"{curr_model}(Exception)")
                logger.warning(f"⚠️ 模型 [{curr_model}] 异常，准备切换: {e}")

        # 所有模型均失败
        final_error = f"Error: 所有模型均失效. 轨迹: {'->'.join(retry_history)}"
        logger.error(f"❌ {final_error}")
        return {} if require_json else final_error

    def shutdown(self):
        """关闭客户端，停止配置监控器"""
        if hasattr(self, '_config_watcher'):
            self._config_watcher.stop()
        logger.info("AIHubClient 已关闭")


# 全局单例 AI 客户端
client = AIHubClient(
    api_key=API_KEY,
    base_url=BASE_URL,
    config_file=DEFAULT_CONFIG_PATH,
    timeout=30
)