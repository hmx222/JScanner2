import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import List, Optional

import json_repair
from openai import OpenAI, APIConnectionError, APIStatusError, RateLimitError, APITimeoutError

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "config/config.json"

class EmptyContentError(Exception):
    """模型返回空内容异常，用于触发故障转移重试"""
    pass


@dataclass
class ModelStatus:
    model_name: str
    is_available: bool = True
    cooldown_until: float = 0.0
    error_count: int = 0
    COOLDOWN_BASE = 30
    MAX_COOLDOWN = 600

    def get_cooldown_time(self) -> int:
        return min(self.error_count * self.COOLDOWN_BASE, self.MAX_COOLDOWN)

    def mark_error(self, error_msg: str):
        self.error_count += 1
        cooldown_seconds = self.get_cooldown_time()
        self.cooldown_until = time.time() + cooldown_seconds
        self.is_available = False
        logger.warning(
            f"❌ 模型 [{self.model_name}] 发生错误({error_msg}) -> 进入冷却 | "
            f"错误次数：{self.error_count} | 冷却时间：{cooldown_seconds}秒"
        )

    def mark_success(self):
        if self.error_count > 0:
            logger.info(f"✅ 模型 [{self.model_name}] 恢复正常，重置错误计数")
        self.error_count = 0
        self.is_available = True
        self.cooldown_until = 0.0

    def check_and_restore(self) -> bool:
        if not self.is_available and time.time() >= self.cooldown_until:
            self.is_available = True
            self.cooldown_until = 0.0
            logger.info(f"🔄 模型 [{self.model_name}] 冷却到期，重新投入池中")
            return True
        return False


class ConfigWatcher(threading.Thread):
    def __init__(self, file_path: str, client_ref: 'AIHubClient', interval: int = 30):
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
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            new_models = config.get('models', [])
            if not new_models: return
            with self.client_ref._lock:
                self.client_ref._models = new_models
                self.client_ref._model_statuses = [ModelStatus(model_name=m) for m in new_models]
            logger.info(f"📥 模型配置热更新成功：{new_models}")
        except Exception as e:
            logger.error(f"配置加载失败：{e}")

    def stop(self):
        self.running = False


class AIHubClient:
    def __init__(self, api_key: str, base_url: str, models: List[str] = None,
                 config_file: str = None, timeout: int = 180):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self._config_file = config_file
        self._client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout, max_retries=0)

        self._client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=timeout,
            max_retries=0
        )

        # 加载初始模型列表
        if not models and config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                models = config.get('models', [])
            except Exception as e:
                logger.warning(f"配置文件读取失败：{e}")

        self._models = models or []
        self._model_statuses = [ModelStatus(model_name=m) for m in self._models]
        self._lock = threading.Lock()

        if config_file:
            self._config_watcher = ConfigWatcher(config_file, self, interval=30)
            self._config_watcher.start()

        logger.info(f"🚀 AIHubClient (SDK版) 初始化完成 | 代理模型数：{len(self._models)}")

    def _get_available_model(self) -> Optional[ModelStatus]:
        with self._lock:
            for status in self._model_statuses:
                status.check_and_restore()
            for status in self._model_statuses:
                if status.is_available:
                    return status
            return None

    def _clean_content(self, text: str) -> str:
        """全局硬核清洗：剔除所有深度思考标签及其内容"""
        if not text: return ""
        # 1. 剔除 <think>...</think>
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)
        # 2. 剔除 Markdown 代码块标记（可选，方便直接解析内容）
        text = re.sub(r'```json\s*|```', '', text).strip()
        return text

    def chat(self, messages: list, require_json: bool = False, **kwargs) -> any:
        # 自动注入全局禁用思考的参数（针对支持该参数的 Provider）
        extra_body = kwargs.pop("extra_body", {})
        extra_body["enable_thinking"] = False

        # 如果要求 JSON，自动设置 SDK 响应格式
        if require_json:
            kwargs["response_format"] = {"type": "json_object"}

        retry_history = []
        max_attempts = len(self._model_statuses)

        for _ in range(max_attempts):
            model_status = self._get_available_model()
            if not model_status: break

            curr_model = model_status.model_name
            try:
                # SDK 请求
                response = self._client.chat.completions.create(
                    model=curr_model,
                    messages=messages,
                    extra_body=extra_body,
                    **kwargs
                )

                raw_text = response.choices[0].message.content
                if not raw_text: raise ValueError("Empty Response")

                # 标记成功并清洗内容
                model_status.mark_success()
                final_text = self._clean_content(raw_text)

                if require_json:
                    # 尝试解析 JSON
                    obj = json_repair.repair_json(final_text, return_objects=True)
                    if isinstance(obj, (dict, list)): return obj
                    raise ValueError("JSON Repair Failed")

                return final_text

            except (APIConnectionError, APITimeoutError, RateLimitError) as e:
                model_status.mark_error(f"Network/Limit: {type(e).__name__}")
                retry_history.append(f"{curr_model}(Error)")
            except APIStatusError as e:
                if e.status_code >= 500:
                    model_status.mark_error(f"Server Error: {e.status_code}")
                    retry_history.append(f"{curr_model}({e.status_code})")
                else:
                    return f"Error: Client Error {e.status_code}"  # 4xx 不重试
            except Exception as e:
                model_status.mark_error(f"Logic Error: {str(e)}")
                retry_history.append(f"{curr_model}(Exception)")

        return {} if require_json else f"Error: 所有模型均失效. 轨迹: {'->'.join(retry_history)}"

    def shutdown(self):
        if hasattr(self, '_config_watcher'):
            self._config_watcher.stop()
        logger.info("AIHubClient 已关闭")


client = AIHubClient(
        api_key="sk-ERsIPn2b4NxXRii100dwPIAFKmWBAM6MAHEccpeUwfCzbMAV",
        base_url="http://127.0.0.1:3000/v1",
        config_file=DEFAULT_CONFIG_PATH,
        timeout=30
    )


if __name__ == "__main__":

    # 测试 1: 普通对话（包含清洗思考过程的功能）
    print("--- 测试普通对话 ---")
    messages = [{"role": "user", "content": "你好，用一句话介绍维多利亚3这个游戏。"}]
    # 哪怕模型返回了 <think>这是个P社游戏...</think> 维多利亚3是... ，也会被自动清洗
    result = client.chat(messages=messages, require_json=False)
    print("响应内容:", result)

    # 测试 2: 强制要求输出 JSON，并开启重试机制
    print("\n--- 测试强 JSON 输出与故障转移 ---")
    messages_json = [
        {"role": "system", "content": "你是一个信息提取器。必须以 JSON 格式输出，包含字段 name 和 age。"},
        {"role": "user", "content": "张三今年25岁"}
    ]
    # 调用时指定 require_json=True
    json_result = client.chat(messages=messages_json, require_json=True)
    print("JSON 响应:", type(json_result), json_result)

    client.shutdown()