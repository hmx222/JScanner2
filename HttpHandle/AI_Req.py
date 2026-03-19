import requests
import json
import time
import logging
import threading
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from json_repair import repair_json

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ==================== 自定义异常 ====================

class EmptyContentError(Exception):
    """
    模型返回空内容异常。
    用于触发故障转移重试。
    """
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
            f"模型 [{self.model_name}] 发生错误，进入冷却状态 | "
            f"错误次数：{self.error_count} | 冷却时间：{cooldown_seconds}秒 | "
            f"恢复时间：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.cooldown_until))}"
        )

    def mark_success(self):
        """标记成功，重置错误计数"""
        if self.error_count > 0:
            logger.info(
                f"模型 [{self.model_name}] 请求成功，重置错误计数 | "
                f"原错误次数：{self.error_count}"
            )
        self.error_count = 0
        self.is_available = True
        self.cooldown_until = 0.0

    def check_and_restore(self) -> bool:
        """检查是否冷却到期，到期则恢复可用状态"""
        if not self.is_available and time.time() >= self.cooldown_until:
            self.is_available = True
            self.cooldown_until = 0.0
            logger.info(
                f"模型 [{self.model_name}] 冷却到期，恢复可用状态 | "
                f"保留错误计数：{self.error_count}"
            )
            return True
        return False


# ==================== 主客户端类 ====================

class AIHubClient:
    def __init__(self, api_key: str, base_url: str, models: List[str]):
        """
        初始化客户端（支持多模型故障转移）

        :param api_key: API 密钥
        :param base_url: 服务地址 (如 http://127.0.0.1:8000/v1)
        :param models: 模型名称列表（按优先级排序，第一个优先级最高）
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')

        # 初始化模型状态列表（保持优先级顺序）
        self._models = models
        self._model_statuses: List[ModelStatus] = [
            ModelStatus(model_name=m) for m in models
        ]

        # 线程锁，保护模型状态
        self._lock = threading.Lock()

        # 默认请求超时时间
        self._timeout = 180

        logger.info(f"AIHubClient 初始化完成 | 模型列表：{models} | 数量：{len(models)}")

    def _check_all_models_restore(self):
        """检查所有模型是否有冷却到期的，恢复可用状态"""
        with self._lock:
            for status in self._model_statuses:
                status.check_and_restore()

    def _get_available_model(self) -> Optional[ModelStatus]:
        """
        获取当前可用的最高优先级模型

        :return: 可用的模型状态，如果无可用模型则返回 None
        """
        # 先检查并恢复冷却到期的模型
        self._check_all_models_restore()

        with self._lock:
            for status in self._model_statuses:
                if status.is_available:
                    return status
            return None

    def _get_all_unavailable_info(self) -> str:
        """获取所有不可用模型的信息（用于最终错误提示）"""
        info = []
        with self._lock:
            for status in self._model_statuses:
                if not status.is_available:
                    remaining = status.cooldown_until - time.time()
                    info.append(
                        f"{status.model_name}(错误{status.error_count}次，"
                        f"剩余{max(0, int(remaining))}秒)"
                    )
        return ", ".join(info) if info else "无"

    def _make_request(self, model_name: str, payload: dict) -> requests.Response:
        """
        发起实际的 HTTP 请求

        :param model_name: 模型名称
        :param payload: 请求体
        :return: requests Response 对象
        """
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=self._timeout,
            stream=payload.get("stream", False)
        )
        return response

    def _is_retryable_error(self, status_code: int, exception: Exception = None) -> bool:
        """
        判断错误是否可重试

        :param status_code: HTTP 状态码（None 表示网络异常）
        :param exception: 异常对象
        :return: True 表示可重试，False 表示不可重试
        """
        # 网络异常（超时、连接错误等）- 可重试
        if status_code is None:
            return True

        # 5xx 服务端错误 - 可重试
        if 500 <= status_code < 600:
            return True

        # 4xx 客户端错误 - 不可重试
        if 400 <= status_code < 500:
            return False

        # 其他状态码 - 可重试
        return True

    def chat(self,
             messages: List[Dict[str, str]],
             model: Optional[str] = None,
             max_tokens: int = 1024,
             temperature: float = 0.7,
             top_p: float = 1.0,
             stream: bool = False,
             stop: Optional[List[str]] = None,
             **extra_kwargs):
        """
        对话函数（支持多模型故障转移 + 冷却重试）

        :param messages: 消息列表
        :param model: 指定模型（可选，不指定则自动选择）
        :param max_tokens: 最大生成 token 数
        :param temperature: 温度值
        :param top_p: 核采样参数
        :param stream: 是否流式响应
        :param stop: 停止词列表
        :param extra_kwargs: 其他扩展参数
        :return: AI 返回的文本内容 (非流式) 或 生成器 (流式)
        """
        # 构建基础 payload
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
            "stream": stream
        }

        if stop:
            payload["stop"] = stop
        if extra_kwargs:
            payload.update(extra_kwargs)

        # 记录重试历史
        retry_history = []
        max_retries = len(self._model_statuses)

        for attempt in range(max_retries):
            # 获取可用模型
            available_model = self._get_available_model()

            if available_model is None:
                unavailable_info = self._get_all_unavailable_info()
                error_msg = (
                    f"所有模型都不可用 | 重试次数：{attempt} | "
                    f"不可用模型：{unavailable_info}"
                )
                logger.error(error_msg)
                return f"Error: {error_msg}"

            # 如果指定了模型，且该模型可用，则使用指定模型
            if model and model != available_model.model_name:
                with self._lock:
                    specified_model_status = next(
                        (s for s in self._model_statuses if s.model_name == model),
                        None
                    )
                if specified_model_status and specified_model_status.is_available:
                    available_model = specified_model_status
                elif specified_model_status and not specified_model_status.is_available:
                    logger.warning(
                        f"指定模型 [{model}] 当前不可用，使用备用模型 [{available_model.model_name}]"
                    )

            current_model = available_model.model_name
            payload["model"] = current_model

            logger.info(
                f"发起请求 (尝试 {attempt + 1}/{max_retries}) | "
                f"使用模型：{current_model}"
            )

            try:
                response = self._make_request(current_model, payload)

                if response.status_code != 200:
                    if self._is_retryable_error(response.status_code):
                        with self._lock:
                            current_status = next(
                                s for s in self._model_statuses
                                if s.model_name == current_model
                            )
                            current_status.mark_error()

                        retry_history.append(
                            f"{current_model}(HTTP {response.status_code})"
                        )
                        logger.warning(
                            f"请求失败，准备切换模型 | "
                            f"状态码：{response.status_code}"
                        )
                        continue
                    else:
                        error_msg = (
                            f"不可重试的错误 | 模型：{current_model} | "
                            f"状态码：{response.status_code} | 响应：{response.text}"
                        )
                        logger.error(error_msg)
                        return f"Error: {error_msg}"

                # 请求成功
                with self._lock:
                    current_status = next(
                        s for s in self._model_statuses
                        if s.model_name == current_model
                    )
                    current_status.mark_success()

                # 处理流式响应
                if stream:
                    if retry_history:
                        logger.info(
                            f"流式请求成功 | 模型：{current_model} | "
                            f"之前失败过：{' → '.join(retry_history)}"
                        )
                    return self._stream_handler(response)

                # 处理非流式响应
                result = response.json()
                content = result['choices'][0]['message']['content']

                # 【关键修改】检查空内容（None 或 空字符串）
                if content is None or (isinstance(content, str) and content.strip() == ""):
                    raise EmptyContentError(f"模型返回空内容 | 模型：{current_model}")

                if retry_history:
                    logger.info(
                        f"请求成功 | 模型：{current_model} | "
                        f"之前失败过：{' → '.join(retry_history)}"
                    )
                else:
                    logger.debug(f"请求成功 | 模型：{current_model}")

                return content

            except EmptyContentError as e:
                # 【新增】空内容错误 - 可重试
                logger.warning(f"空内容错误 | 模型：{current_model} | 错误：{str(e)}")
                with self._lock:
                    current_status = next(
                        s for s in self._model_statuses
                        if s.model_name == current_model
                    )
                    current_status.mark_error()

                retry_history.append(f"{current_model}(EmptyContent)")
                continue

            except requests.exceptions.Timeout as e:
                logger.warning(f"请求超时 | 模型：{current_model} | 错误：{str(e)}")
                with self._lock:
                    current_status = next(
                        s for s in self._model_statuses
                        if s.model_name == current_model
                    )
                    current_status.mark_error()

                retry_history.append(f"{current_model}(Timeout)")
                continue

            except requests.exceptions.ConnectionError as e:
                logger.warning(f"连接错误 | 模型：{current_model} | 错误：{str(e)}")
                with self._lock:
                    current_status = next(
                        s for s in self._model_statuses
                        if s.model_name == current_model
                    )
                    current_status.mark_error()

                retry_history.append(f"{current_model}(ConnectionError)")
                continue

            except requests.exceptions.RequestException as e:
                logger.warning(f"网络异常 | 模型：{current_model} | 错误：{str(e)}")
                with self._lock:
                    current_status = next(
                        s for s in self._model_statuses
                        if s.model_name == current_model
                    )
                    current_status.mark_error()

                retry_history.append(f"{current_model}(RequestException)")
                continue

            except Exception as e:
                logger.error(f"未知异常 | 模型：{current_model} | 错误：{str(e)}")
                with self._lock:
                    current_status = next(
                        s for s in self._model_statuses
                        if s.model_name == current_model
                    )
                    current_status.mark_error()

                retry_history.append(f"{current_model}(Exception)")
                continue

        # 所有重试都失败
        final_error = (
            f"所有模型重试失败 | 失败历史：{' → '.join(retry_history)} | "
            f"当前不可用模型：{self._get_all_unavailable_info()}"
        )
        logger.error(final_error)
        return f"Error: {final_error}"

    def _stream_handler(self, response):
        """处理流式响应"""
        for line in response.iter_lines():
            if line:
                line = line.decode('utf-8')
                if line.startswith('data: '):
                    data = line[6:]
                    if data.strip() == '[DONE]':
                        break
                    try:
                        chunk = repair_json(data, return_objects=True)
                        if isinstance(chunk, dict):
                            content = chunk['choices'][0]['delta'].get('content', '')
                            if content:
                                yield content
                    except:
                        continue

    def simple_chat(self, message: str, **kwargs):
        """
        简化版对话 (兼容旧代码调用方式)
        :param message: 用户输入的问题
        :param kwargs: 其他参数透传给 chat 方法
        :return: AI 返回的文本内容
        """
        messages = [
            {"role": "user", "content": message}
        ]
        return self.chat(messages=messages, **kwargs)

    def get_model_status(self) -> List[Dict]:
        """
        获取所有模型的当前状态（用于监控/调试）

        :return: 模型状态列表
        """
        self._check_all_models_restore()
        with self._lock:
            return [
                {
                    "model": s.model_name,
                    "available": s.is_available,
                    "error_count": s.error_count,
                    "cooldown_remaining": max(0, s.cooldown_until - time.time()) if s.cooldown_until > 0 else 0
                }
                for s in self._model_statuses
            ]

    def reset_all_models(self):
        """
        重置所有模型状态（手动恢复，用于调试或紧急情况）
        """
        with self._lock:
            for status in self._model_statuses:
                status.is_available = True
                status.cooldown_until = 0.0
                status.error_count = 0
        logger.info("所有模型状态已重置")

client = AIHubClient(
        api_key="sk-ERsIPn2b4NxXRii100dwPIAFKmWBAM6MAHEccpeUwfCzbMAV",
        base_url="http://127.0.0.1:3000/v1/",
        models=[
            "xopqwen35397b",  # 优先级 1（最高）
            "doubao-seed-code-preview-251028",  # 优先级 2
            "z-ai/glm4.7",  # 优先级 3
        ]
    )

    # 手动重置模型状态
    # client.reset_all_models()