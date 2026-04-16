import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any

import json_repair
from openai import OpenAI, APIConnectionError, APIStatusError, RateLimitError, APITimeoutError

from config.config import BASE_URL, API_KEY, BATCH_BASE_URL, API_KEY_BATCH, POLL_INTERVAL, MAX_WAIT_TIME, \
    MIN_BATCH_THRESHOLD, RECOMMENDED_BATCH_SIZE, MAX_BATCH_SIZE, MAX_BATCH_FILE_SIZE_MB, MAX_SINGLE_REQUEST_SIZE_MB, \
    BATCH_SIZE_SAFETY_FACTOR

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "config/models_config.json"

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
            new_batch_models = config.get('batch_api_models', [])
            if not new_models: return
            with self.client_ref._lock:
                self.client_ref._models = new_models
                self.client_ref._model_statuses = [ModelStatus(model_name=m) for m in new_models]
                self.client_ref._batch_models = new_batch_models
            logger.info(f"📥 模型配置热更新成功 | 普通模型: {new_models} | Batch模型: {new_batch_models}")
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

        # Batch API 客户端（使用专用的 batch endpoint 和独立的 API Key）
        if BATCH_BASE_URL and API_KEY_BATCH:
            self._batch_base_url = BATCH_BASE_URL.rstrip('/')
            self._batch_client = OpenAI(
                api_key=API_KEY_BATCH,
                base_url=self._batch_base_url,
                timeout=timeout,
                max_retries=0
            )
            self.batch_enabled = True
            logger.info(f"📦 Batch API 已启用 | Endpoint: {self._batch_base_url}")
        else:
            self._batch_client = None
            self.batch_enabled = False
            logger.warning("⚠️ Batch API 未配置，将仅使用单调用模式")

        # 加载初始模型列表
        if not models and config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                models = config.get('models', [])
                # 加载 Batch API 专用模型列表
                self._batch_models = config.get('batch_api_models', [])
            except Exception as e:
                logger.warning(f"配置文件读取失败：{e}")
                self._batch_models = []
        else:
            self._batch_models = []

        self._models = models or []
        self._model_statuses = [ModelStatus(model_name=m) for m in self._models]
        self._lock = threading.Lock()

        if config_file:
            self._config_watcher = ConfigWatcher(config_file, self, interval=30)
            self._config_watcher.start()

        # 输出 Batch API 模型配置信息
        if self.batch_enabled:
            batch_model_info = self._batch_models[0] if self._batch_models else "未配置（将使用默认模型）"
            logger.info(f"📦 Batch API 模型: {batch_model_info}")
        
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


    def chat_batch(self, batch_messages: List[Dict[str, Any]], 
                   model: str = None, 
                   require_json: bool = False,
                   max_tokens: int = 2048,
                   temperature: float = 0.1,
                   batch_size: int = None,
                   poll_interval: int = None,
                   max_wait_time: int = None,
                   retry_failed: bool = True,
                   **kwargs) -> List[Any]:
        """
        批量调用大模型（使用 DashScope Batch File API）
        
        Args:
            batch_messages: 批量消息列表，每个元素是 {"custom_id": str, "messages": list, "params": dict}
            model: 指定模型名称，默认使用 batch_api_models 中的第一个模型
            require_json: 是否要求返回 JSON
            max_tokens: 最大 token 数
            temperature: 温度参数
            batch_size: 手动指定批次大小（可选），不指定则自动计算
            poll_interval: 轮询间隔（秒），默认使用 config.py 中的 POLL_INTERVAL
            max_wait_time: 最大等待时间（秒），默认使用 config.py 中的 MAX_WAIT_TIME
            retry_failed: 是否对失败的任务进行重试（默认 True，降级为单调用）
            
        Returns:
            批量结果列表，与输入顺序对应
        """
        if not self.batch_enabled:
            logger.error("❌ Batch API 未启用，无法使用批量调用")
            return [None] * len(batch_messages)
        
        if not batch_messages:
            return []
        
        total_tasks = len(batch_messages)
        
        # 检查是否达到 Batch API 启用阈值
        if total_tasks < MIN_BATCH_THRESHOLD:
            logger.info(f"⚠️ 任务数 {total_tasks} < 阈值 {MIN_BATCH_THRESHOLD}，降级为单调用模式")
            return self._fallback_to_single_calls(batch_messages, model, require_json, max_tokens, temperature, **kwargs)
        
        # 预检查：验证单个请求大小
        oversized_requests = self._check_single_request_sizes(batch_messages)
        if oversized_requests:
            logger.warning(f"⚠️ 发现 {len(oversized_requests)} 个超大请求（> {MAX_SINGLE_REQUEST_SIZE_MB}MB），已自动过滤")
            valid_messages = [msg for i, msg in enumerate(batch_messages) if i not in oversized_requests]
            if not valid_messages:
                logger.error("❌ 所有请求都超过大小限制，无法使用 Batch API")
                return [None] * total_tasks
            batch_messages = valid_messages
            total_tasks = len(batch_messages)
            logger.info(f"✅ 过滤后剩余 {total_tasks} 个有效请求")
        
        # 估算总文件大小
        estimated_total_size_mb = self._estimate_batch_file_size(batch_messages)
        
        # 智能计算批次大小（考虑任务数、文件大小、单行大小限制）
        if batch_size is None:
            actual_batch_size = self._calculate_optimal_batch_size(
                total_tasks, 
                estimated_total_size_mb
            )
        else:
            # 手动指定时，限制在 [MIN_BATCH_THRESHOLD, MAX_BATCH_SIZE] 范围内
            actual_batch_size = max(MIN_BATCH_THRESHOLD, min(batch_size, MAX_BATCH_SIZE))
        
        actual_poll_interval = poll_interval or POLL_INTERVAL
        actual_max_wait_time = max_wait_time or MAX_WAIT_TIME
        
        # 优先使用手动指定的模型，其次使用 batch_api_models 的第一个模型，最后兜底
        selected_model = model or (self._batch_models[0] if self._batch_models else (self._models[0] if self._models else "qwen-plus"))
        
        # 计算分批信息
        total_batches = (total_tasks + actual_batch_size - 1) // actual_batch_size
        estimated_single_batch_size_mb = estimated_total_size_mb / total_batches if total_batches > 0 else 0
        
        logger.info(
            f"📦 开始批量调用 | "
            f"总数: {total_tasks} | "
            f"模型: {selected_model} | "
            f"批次大小: {actual_batch_size} | "
            f"批次数: {total_batches} | "
            f"预估总大小: {estimated_total_size_mb:.2f}MB | "
            f"单批大小: {estimated_single_batch_size_mb:.2f}MB | "
            f"轮询间隔: {actual_poll_interval}秒 | "
            f"最大等待: {actual_max_wait_time}秒 | "
            f"失败重试: {'开启' if retry_failed else '关闭'}"
        )
        
        all_results = []
        
        for batch_idx in range(0, total_tasks, actual_batch_size):
            batch = batch_messages[batch_idx:batch_idx + actual_batch_size]
            current_batch_num = batch_idx // actual_batch_size + 1
            
            logger.info(f"🔄 处理批次 {current_batch_num}/{total_batches} ({len(batch)} 个请求)")
            
            try:
                batch_results = self._process_single_batch(
                    batch=batch,
                    model=selected_model,
                    require_json=require_json,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    poll_interval=actual_poll_interval,
                    max_wait_time=actual_max_wait_time,
                    **kwargs
                )
                
                # 如果开启重试，对失败的任务进行降级处理
                if retry_failed:
                    failed_indices = [i for i, r in enumerate(batch_results) if r is None]
                    if failed_indices:
                        logger.warning(
                            f"⚠️ 批次 {current_batch_num} 中有 {len(failed_indices)} 个任务失败，"
                            f"降级为单调用重试..."
                        )
                        failed_messages = [batch[i] for i in failed_indices]
                        retry_results = self._fallback_to_single_calls(
                            failed_messages, model, require_json, max_tokens, temperature, **kwargs
                        )
                        
                        # 将重试结果填回原位置
                        for original_idx, retry_result in zip(failed_indices, retry_results):
                            batch_results[original_idx] = retry_result
                        
                        logger.info(
                            f"✅ 批次 {current_batch_num} 重试完成 | "
                            f"成功: {sum(1 for r in batch_results if r is not None)}/{len(batch_results)}"
                        )
                
                all_results.extend(batch_results)
                
            except Exception as e:
                logger.error(f"❌ 批次 {current_batch_num} 处理失败: {e}")
                all_results.extend([None] * len(batch))
        
        logger.info(f"✅ 批量调用完成 | 成功: {sum(1 for r in all_results if r is not None)}/{len(all_results)}")
        return all_results
    
    def _check_single_request_sizes(self, batch_messages: List[Dict[str, Any]]) -> set:
        """
        检查单个请求的大小，返回超限的请求索引集合

        Returns:
            超限请求的索引集合
        """
        oversized_indices = set()
        max_size_bytes = MAX_SINGLE_REQUEST_SIZE_MB * 1024 * 1024  # 转换为字节
        
        for idx, item in enumerate(batch_messages):
            custom_id = item.get("custom_id", f"req_{idx}")
            messages = item.get("messages", [])
            params = item.get("params", {})
            
            request_body = {
                "model": "placeholder",
                "messages": messages,
                "max_tokens": params.get("max_tokens", 2048),
                "temperature": params.get("temperature", 0.1),
                **params
            }
            
            jsonl_line = {
                "custom_id": custom_id,
                "method": "POST",
                "url": "/v1/chat/completions",
                "body": request_body
            }
            
            json_str = json.dumps(jsonl_line, ensure_ascii=False)
            size_bytes = len(json_str.encode('utf-8'))
            
            if size_bytes > max_size_bytes:
                oversized_indices.add(idx)
                size_mb = size_bytes / (1024 * 1024)
                logger.warning(
                    f"⚠️ 请求 {custom_id} 超限: {size_mb:.2f}MB > {MAX_SINGLE_REQUEST_SIZE_MB}MB"
                )
        
        return oversized_indices
    
    def _estimate_batch_file_size(self, batch_messages: List[Dict[str, Any]]) -> float:
        """
        估算 Batch API 文件大小（单位：MB）
        """
        total_bytes = 0
        
        for item in batch_messages:
            custom_id = item.get("custom_id", "")
            messages = item.get("messages", [])
            params = item.get("params", {})
            
            request_body = {
                "model": "placeholder",  # 占位符，实际大小差异不大
                "messages": messages,
                "max_tokens": params.get("max_tokens", 2048),
                "temperature": params.get("temperature", 0.1),
                **params
            }
            
            jsonl_line = {
                "custom_id": custom_id,
                "method": "POST",
                "url": "/v1/chat/completions",
                "body": request_body
            }
            
            # 计算 JSON 字符串的 UTF-8 编码字节数
            json_str = json.dumps(jsonl_line, ensure_ascii=False)
            total_bytes += len(json_str.encode('utf-8')) + 1  # +1 为换行符
        
        # 转换为 MB
        total_mb = total_bytes / (1024 * 1024)
        return total_mb
    
    def _calculate_optimal_batch_size(self, total_tasks: int, estimated_total_size_mb: float = 0) -> int:
        """
        智能计算最优批次大小（同时考虑任务数、文件大小、单行大小）
        
        双重约束：
        1. 文件大小 <= MAX_BATCH_FILE_SIZE_MB * SAFETY_FACTOR (400MB * 0.75 = 300MB)
        2. 单行大小 <= MAX_SINGLE_REQUEST_SIZE_MB (5MB) - 已在预处理中过滤
        """
        if total_tasks <= MAX_BATCH_SIZE:
            initial_batch_size = total_tasks
        else:
            # 任务数超过 MAX_BATCH_SIZE，需要分批
            # 尝试找到一个合适的批次大小，使得最后一批不至于太小
            initial_batch_size = RECOMMENDED_BATCH_SIZE
            for batch_size in range(MAX_BATCH_SIZE, RECOMMENDED_BATCH_SIZE - 1, -50):
                remainder = total_tasks % batch_size
                if remainder == 0 or remainder >= MIN_BATCH_THRESHOLD:
                    initial_batch_size = batch_size
                    break

        if estimated_total_size_mb > 0 and total_tasks > 0:
            # 计算单个任务的平均大小
            avg_task_size_mb = estimated_total_size_mb / total_tasks
            
            # 根据文件大小限制计算最大允许的任务数
            max_tasks_by_size = int(
                (MAX_BATCH_FILE_SIZE_MB * BATCH_SIZE_SAFETY_FACTOR) / avg_task_size_mb
            )
            
            # 取两者中的较小值
            final_batch_size = min(initial_batch_size, max_tasks_by_size)
            
            # 确保不小于最小阈值
            final_batch_size = max(final_batch_size, MIN_BATCH_THRESHOLD)
            
            # 确保不超过最大限制
            final_batch_size = min(final_batch_size, MAX_BATCH_SIZE)
            
            logger.debug(
                f"📊 批次大小计算 | "
                f"基于任务数: {initial_batch_size} | "
                f"基于文件大小: {max_tasks_by_size} | "
                f"最终选择: {final_batch_size}"
            )
            
            return final_batch_size
        
        return initial_batch_size
    
    def _fallback_to_single_calls(self, batch_messages: List[Dict[str, Any]], 
                                  model: str = None, 
                                  require_json: bool = False,
                                  max_tokens: int = 2048,
                                  temperature: float = 0.1,
                                  **kwargs) -> List[Any]:
        """降级为单调用模式"""
        logger.info(f"🔄 降级为单调用模式处理 {len(batch_messages)} 个任务")
        
        selected_model = model or (self._batch_models[0] if self._batch_models else (self._models[0] if self._models else "qwen-plus"))
        results = []
        
        for idx, item in enumerate(batch_messages):
            try:
                messages = item.get("messages", [])
                params = item.get("params", {})
                
                response = self._client.chat.completions.create(
                    model=selected_model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    **params,
                    **kwargs
                )
                
                raw_text = response.choices[0].message.content
                if require_json:
                    cleaned = self._clean_content(raw_text)
                    obj = json_repair.repair_json(cleaned, return_objects=True)
                    results.append(obj if isinstance(obj, (dict, list)) else None)
                else:
                    results.append(self._clean_content(raw_text))
                    
            except Exception as e:
                logger.error(f"❌ 单调用任务 {idx} 失败: {e}")
                results.append(None)
        
        return results

    def _process_single_batch(self, batch: List[Dict], model: str, 
                             require_json: bool, max_tokens: int, 
                             temperature: float, poll_interval: int,
                             max_wait_time: int, **kwargs) -> List[Any]:
        """处理单个批次的批量请求"""
        import tempfile
        
        jsonl_lines = []
        custom_id_map = {}
        
        for idx, item in enumerate(batch):
            custom_id = item.get("custom_id", f"req_{idx}")
            messages = item.get("messages", [])
            params = item.get("params", {})
            
            request_body = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                **params
            }
            
            if require_json:
                request_body["response_format"] = {"type": "json_object"}
            
            jsonl_line = {
                "custom_id": custom_id,
                "method": "POST",
                "url": "/v1/chat/completions",
                "body": request_body
            }
            
            jsonl_lines.append(json.dumps(jsonl_line, ensure_ascii=False))
            custom_id_map[custom_id] = idx
        
        jsonl_content = "\n".join(jsonl_lines)
        
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False, encoding='utf-8') as f:
                f.write(jsonl_content)
                temp_file = f.name
            
            file_id = self._upload_batch_file(temp_file)
            if not file_id:
                raise Exception("文件上传失败")
            
            batch_id = self._create_batch_job(file_id)
            if not batch_id:
                raise Exception("创建 Batch 任务失败")
            
            logger.info(f"📤 Batch 任务已提交 | Batch ID: {batch_id}")
            
            output_file_id = self._wait_for_completion(batch_id, poll_interval, max_wait_time)
            if not output_file_id:
                raise Exception("任务未完成或失败")
            
            results = self._download_and_parse_results(output_file_id, custom_id_map, len(batch))
            return results
            
        finally:
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass
    
    def _upload_batch_file(self, file_path: str) -> Optional[str]:
        """上传 JSONL 文件到 DashScope"""
        try:
            file_object = self._batch_client.files.create(
                file=Path(file_path),
                purpose="batch"
            )
            logger.info(f"📁 文件上传成功 | File ID: {file_object.id}")
            return file_object.id
        except Exception as e:
            logger.error(f"❌ 文件上传失败: {e}")
            return None
    
    def _create_batch_job(self, input_file_id: str) -> Optional[str]:
        """创建 Batch 任务"""
        try:
            batch = self._batch_client.batches.create(
                input_file_id=input_file_id,
                endpoint="/v1/chat/completions",
                completion_window="24h"
            )
            return batch.id
        except Exception as e:
            logger.error(f"❌ 创建 Batch 任务失败: {e}")
            return None
    
    def _wait_for_completion(self, batch_id: str, poll_interval: int, 
                            max_wait_time: int) -> Optional[str]:
        """等待 Batch 任务完成"""
        start_time = time.time()
        poll_count = 0
        
        while time.time() - start_time < max_wait_time:
            try:
                batch_info = self._batch_client.batches.retrieve(batch_id)
                status = batch_info.status
                poll_count += 1
                
                if status == "completed":
                    logger.info(f"✅ Batch 任务完成 | 轮询次数: {poll_count}")
                    return batch_info.output_file_id
                elif status in ["failed", "expired", "cancelled"]:
                    logger.error(f"❌ Batch 任务异常结束 | 状态: {status}")
                    if batch_info.error_file_id:
                        logger.error(f"错误文件 ID: {batch_info.error_file_id}")
                    return None
                else:
                    logger.debug(f"⏳ 任务状态: {status} | 等待 {poll_interval} 秒...")
                    time.sleep(poll_interval)
                    
            except Exception as e:
                logger.warning(f"⚠️ 查询任务状态失败: {e}")
                time.sleep(poll_interval)
        
        logger.error(f"⏰ 等待超时 | 最大等待时间: {max_wait_time} 秒")
        return None
    
    def _download_and_parse_results(self, output_file_id: str, 
                                   custom_id_map: Dict[str, int],
                                   batch_size: int) -> List[Any]:
        """下载并解析 Batch 结果"""
        try:
            file_response = self._batch_client.files.content(output_file_id)
            content = file_response.text if hasattr(file_response, 'text') else file_response.read().decode('utf-8')
            
            results = [None] * batch_size
            
            for line in content.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    result_obj = json.loads(line)
                    custom_id = result_obj.get("custom_id")
                    
                    if custom_id in custom_id_map:
                        idx = custom_id_map[custom_id]
                        
                        response_body = result_obj.get("response", {}).get("body", {})
                        choices = response_body.get("choices", [])
                        
                        if choices:
                            raw_text = choices[0].get("message", {}).get("content", "")
                            
                            if raw_text:
                                cleaned_text = self._clean_content(raw_text)
                                
                                if result_obj.get("response", {}).get("body", {}).get("response_format", {}).get("type") == "json_object":
                                    try:
                                        parsed = json_repair.repair_json(cleaned_text, return_objects=True)
                                        if isinstance(parsed, (dict, list)):
                                            results[idx] = parsed
                                            continue
                                    except:
                                        pass
                                
                                results[idx] = cleaned_text
                            else:
                                logger.warning(f"⚠️ 请求 {custom_id} 返回空内容")
                        else:
                            error_info = result_obj.get("error", {})
                            logger.error(f"❌ 请求 {custom_id} 失败: {error_info}")
                    
                except Exception as e:
                    logger.error(f"❌ 解析结果行失败: {e}")
                    continue
            
            return results
            
        except Exception as e:
            logger.error(f"❌ 下载结果失败: {e}")
            return [None] * batch_size

    def shutdown(self):
        if hasattr(self, '_config_watcher'):
            self._config_watcher.stop()
        logger.info("AIHubClient 已关闭")


client = AIHubClient(
        api_key=API_KEY,
        base_url=BASE_URL,
        config_file=DEFAULT_CONFIG_PATH,
        timeout=30
    )


