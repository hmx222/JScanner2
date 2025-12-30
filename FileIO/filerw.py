import json
import os
import queue
import re
import threading

import chardet


def read(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read(1000)
        result = chardet.detect(raw_data)
        encoding = result['encoding']

    with open(file_path, 'r', encoding=encoding) as f:
        content_list = f.readlines()

    cleaned_content_list = []
    for line in content_list:
        cleaned_line = re.sub(r'\s+', ' ', line).strip()
        cleaned_content_list.append(cleaned_line)

    return cleaned_content_list


_write_queue = queue.Queue()
_writer_started = False
_writer_lock = threading.Lock()


def _json_writer(file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "a", encoding="utf-8") as f:
        while True:
            item = _write_queue.get()
            if item is None:
                break
            # 仅添加 indent=4，其余逻辑不变
            f.write(json.dumps(item, ensure_ascii=False, indent=4) + "\n")
            f.flush()
            _write_queue.task_done()


def _ensure_writer_started(file_path):
    global _writer_started
    with _writer_lock:
        if not _writer_started:
            t = threading.Thread(
                target=_json_writer,
                args=(file_path,),
                daemon=True
            )
            t.start()
            _writer_started = True

def write2json(file_path, json_str):
    """
    保持原有语义：
    - 接收 json 字符串
    - 写入文件
    """
    _ensure_writer_started(file_path)

    try:
        obj = json.loads(json_str)
    except Exception:
        return

    _write_queue.put(obj)

def clear_or_create_file(file_path):
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write('')
