import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import List, Dict, Optional

import json_repair
import requests

from config.config import CONFIG_TEMPLATE, DEFAULT_CONFIG_PATH, API_KEY, BASE_URL
from logger import get_logger

logger = get_logger(__name__)



# ==================== 自定义异常 ====================
class EmptyContentError(Exception):
    """模型返回空内容异常，用于触发故障转移重试"""
    pass


class ModelListUpdateError(Exception):
    """模型列表更新失败异常"""
    pass


# ==================== 数据类 ====================
@dataclass
class ModelStatus:
    """模型状态数据类"""
    model_name: str
    is_available: bool = True
    cooldown_until: float = 0.0  # 冷却结束时间戳
    error_count: int = 0

    # 常量配置
    COOLDOWN_BASE = 30  # 基础冷却时间 30 秒
    MAX_COOLDOWN = 600  # 最大冷却时间 600 秒

    def get_cooldown_time(self) -> int:
        """根据错误次数计算冷却时间"""
        return min(self.error_count * self.COOLDOWN_BASE, self.MAX_COOLDOWN)

    def mark_error(self):
        """标记错误，更新冷却时间"""
        self.error_count += 1
        cooldown_seconds = self.get_cooldown_time()
        self.cooldown_until = time.time() + cooldown_seconds
        self.is_available = False
        logger.warning(
            f"模型 [{self.model_name}] 进入冷却 | 错误次数：{self.error_count} | "
            f"冷却时间：{cooldown_seconds}秒"
        )

    def mark_success(self):
        """标记成功，重置错误计数"""
        if self.error_count > 0:
            logger.info(f"模型 [{self.model_name}] 重置错误计数")
        self.error_count = 0
        self.is_available = True
        self.cooldown_until = 0.0

    def check_and_restore(self) -> bool:
        """检查是否冷却到期，到期则恢复可用状态"""
        if not self.is_available and time.time() >= self.cooldown_until:
            self.is_available = True
            self.cooldown_until = 0.0
            logger.info(f"模型 [{self.model_name}] 冷却到期恢复")
            return True
        return False


# ==================== 配置文件监控线程 ====================
class ConfigWatcher(threading.Thread):
    """配置文件监控线程，实现模型列表热加载"""

    def __init__(self, file_path: str, client_ref: 'AIHubClient', interval: int = 30):
        super().__init__(daemon=True)
        self.file_path = file_path
        self.client_ref = client_ref
        self.interval = interval
        self.running = True

        try:
            self.last_modified = os.path.getmtime(file_path)
            logger.info(f"ConfigWatcher 启动 | {file_path}")
        except FileNotFoundError:
            logger.error(f"配置文件不存在：{file_path}")
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
            if len(new_models) == 0:
                logger.warning("配置文件 models 为空")
                return
            with self.client_ref._lock:
                old_list = [m.model_name for m in self.client_ref._model_statuses]
                self.client_ref._models = new_models
                self.client_ref._model_statuses = [
                    ModelStatus(model_name=m) for m in new_models
                ]
            logger.info(f"模型配置更新：{old_list} → {new_models}")
        except Exception as e:
            logger.error(f"配置加载失败：{e}")

    def stop(self):
        self.running = False
        logger.info("ConfigWatcher 已停止")


# ==================== AIHubClient 主类 ====================
class AIHubClient:
    def __init__(self, api_key: str, base_url: str, models: List[str],
                 config_file: str = None, timeout: int = 180):
        """
        初始化客户端（支持多模型故障转移 + 配置热加载）

        Args:
            api_key: API 密钥
            base_url: 服务地址
            models: 模型名称列表（优先级排序，为空时从配置文件读取）
            config_file: 配置文件路径（启用热加载则传路径）
            timeout: 请求超时时间（秒）
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._config_file = config_file

        if not models and config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                models = config.get('models', [])
                if models:
                    logger.info(f"从配置文件加载初始模型：{models}")
                else:
                    logger.warning("配置文件中 models 为空，使用空模型列表")
            except Exception as e:
                logger.warning(f"配置文件读取失败：{e}，使用空模型列表")

        # 初始化模型状态列表（保持优先级顺序）
        self._models = models
        self._model_statuses: List[ModelStatus] = [
            ModelStatus(model_name=m) for m in models
        ]

        # 线程锁，保护模型状态
        self._lock = threading.Lock()

        # 配置监控器
        self._config_watcher: Optional[ConfigWatcher] = None

        if config_file:
            self._start_config_watcher(interval=30)

        logger.info(f"AIHubClient 初始化完成 | 模型数：{len(models)} | 热加载：{'是' if config_file else '否'}")

    def _start_config_watcher(self, interval: int = 30):
        if not self._config_file:
            return
        self._config_watcher = ConfigWatcher(self._config_file, self, interval=interval)
        self._config_watcher.start()

    def _check_all_models_restore(self):
        with self._lock:
            for status in self._model_statuses:
                status.check_and_restore()

    def _get_available_model(self) -> Optional[ModelStatus]:
        self._check_all_models_restore()
        with self._lock:
            for status in self._model_statuses:
                if status.is_available:
                    return status
            return None

    def _get_all_unavailable_info(self) -> str:
        info = []
        with self._lock:
            for status in self._model_statuses:
                if not status.is_available:
                    remaining = max(0, status.cooldown_until - time.time())
                    info.append(f"{status.model_name}(错误{status.error_count}次，剩余{int(remaining)}秒)")
        return ", ".join(info) if info else "无"

    def _make_request(self, model_name: str, payload: dict) -> requests.Response:
        url = f"{self.base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        response = requests.post(url, headers=headers, json=payload, timeout=self.timeout, stream=payload.get("stream", False))
        return response

    def _is_retryable_error(self, status_code: int, exception: Exception = None) -> bool:
        if status_code is None:
            return True
        if 500 <= status_code < 600:
            return True
        if 400 <= status_code < 500:
            return False
        return True

    def chat(self, messages: List[Dict[str, str]], model: Optional[str] = None,
             max_tokens: int = 1024, temperature: float = 0.7, top_p: float = 1.0,
             stream: bool = False, stop: Optional[List[str]] = None, **extra_kwargs):
        payload = {
            "model": model, "messages": messages, "max_tokens": max_tokens,
            "temperature": temperature, "top_p": top_p, "stream": stream,"enable_thinking": False,
        }
        if stop:
            payload["stop"] = stop
        if extra_kwargs:
            payload.update(extra_kwargs)

        retry_history = []
        max_retries = len(self._model_statuses)

        for attempt in range(max_retries):
            available_model = self._get_available_model()
            if available_model is None:
                unavailable_info = self._get_all_unavailable_info()
                logger.error(f"所有模型不可用：{unavailable_info}")
                return f"Error: 所有模型都不可用"

            if model and model != available_model.model_name:
                with self._lock:
                    specified_status = next((s for s in self._model_statuses if s.model_name == model), None)
                if specified_status and specified_status.is_available:
                    available_model = specified_status
                elif specified_status and not specified_status.is_available:
                    logger.warning(f"指定模型不可用，切换至备用：{available_model.model_name}")

            current_model = available_model.model_name
            payload["model"] = current_model

            try:
                response = self._make_request(current_model, payload)

                if response.status_code != 200:
                    if self._is_retryable_error(response.status_code):
                        with self._lock:
                            current_status = next(s for s in self._model_statuses if s.model_name == current_model)
                            current_status.mark_error()
                        retry_history.append(f"{current_model}(HTTP {response.status_code})")
                        continue
                    else:
                        logger.error(f"不可重试错误：{response.status_code}")
                        return f"Error: 不可重试错误"

                with self._lock:
                    current_status = next(s for s in self._model_statuses if s.model_name == current_model)
                    current_status.mark_success()

                if stream:
                    return self._stream_handler(response)

                result = response.json()
                content = result['choices'][0]['message']['content']
                if content is None or (isinstance(content, str) and content.strip() == ""):
                    raise EmptyContentError("模型返回空内容")

                return content

            except EmptyContentError as e:
                with self._lock:
                    current_status = next(s for s in self._model_statuses if s.model_name == current_model)
                    current_status.mark_error()
                retry_history.append(f"{current_model}(EmptyContent)")
                continue

            except requests.exceptions.Timeout as e:
                with self._lock:
                    current_status = next(s for s in self._model_statuses if s.model_name == current_model)
                    current_status.mark_error()
                retry_history.append(f"{current_model}(Timeout)")
                continue

            except requests.exceptions.ConnectionError as e:
                with self._lock:
                    current_status = next(s for s in self._model_statuses if s.model_name == current_model)
                    current_status.mark_error()
                retry_history.append(f"{current_model}(ConnectionError)")
                continue

            except requests.exceptions.RequestException as e:
                with self._lock:
                    current_status = next(s for s in self._model_statuses if s.model_name == current_model)
                    current_status.mark_error()
                retry_history.append(f"{current_model}(RequestException)")
                continue

            except Exception as e:
                with self._lock:
                    current_status = next(s for s in self._model_statuses if s.model_name == current_model)
                    current_status.mark_error()
                retry_history.append(f"{current_model}(Exception: {str(e)})")
                continue

        return f"Error: 所有模型重试失败，历史：{' → '.join(retry_history)}"

    def _stream_handler(self, response):
        for line in response.iter_lines():
            if line:
                line = line.decode('utf-8')
                if line.startswith('data: '):
                    data = line[6:]
                    if data.strip() == '[DONE]':
                        break
                    try:
                        chunk = json_repair.repair_json(data, return_objects=True)
                        if isinstance(chunk, dict):
                            content = chunk.get('choices', [{}])[0].get('delta', {}).get('content', '')
                            if content:
                                yield content
                    except:
                        continue

    def simple_chat(self, message: str, **kwargs):
        return self.chat(messages=[{"role": "user", "content": message}], **kwargs)

    def get_model_status(self) -> List[Dict]:
        with self._lock:
            return [
                {"model": s.model_name, "available": s.is_available,
                 "error_count": s.error_count,
                 "cooldown_remaining": max(0, s.cooldown_until - time.time()) if s.cooldown_until > 0 else 0}
                for s in self._model_statuses
            ]

    def reset_all_models(self):
        with self._lock:
            for status in self._model_statuses:
                status.is_available = True
                status.cooldown_until = 0.0
                status.error_count = 0
        logger.info("所有模型状态已重置")

    def shutdown(self):
        if self._config_watcher:
            self._config_watcher.stop()
        logger.info("AIHubClient 已关闭")



def init_config_file(config_path: str = DEFAULT_CONFIG_PATH):
    """初始化配置文件（仅当文件不存在时创建）"""
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    if not os.path.exists(config_path):
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(CONFIG_TEMPLATE)
        logger.info(f"配置文件已创建：{config_path}")
    else:
        logger.info(f"配置文件已存在：{config_path}")



init_config_file(DEFAULT_CONFIG_PATH)

client = AIHubClient(
    api_key=API_KEY,
    base_url=BASE_URL,
    models=[],
    config_file=DEFAULT_CONFIG_PATH,
    timeout=180
)

