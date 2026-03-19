import json
import pymysql
import os
import time

# --- 1. 配置区域 ---

DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 3306,
    'user': 'root',
    'password': 'root',
    'db': 'test',
    'charset': 'utf8mb4',
    'autocommit': False,
    'cursorclass': pymysql.cursors.DictCursor
}

JSON_FILE = 'results.json'
TABLE_NAME = 'loud'
BATCH_SIZE = 5000

FIELD_MAPPING = {
    'cdn_name': 'cname',
    'body_domains': 'a',
}
JSON_TO_DB_MAPPING = {v: k for k, v in FIELD_MAPPING.items()}


# --- 2. 辅助函数 ---

def get_connection():
    return pymysql.connect(**DB_CONFIG)


def infer_sql_type(value):
    if isinstance(value, bool): return "BOOLEAN"  # 实际是 TINYINT
    if isinstance(value, int): return "INT"
    if isinstance(value, float): return "FLOAT"
    return "TEXT"


def clean_value_for_db(val):
    """
    清洗数据：核心修复逻辑在这里
    """
    if val is None:
        return None

    # 🔥【修复重点】优先处理布尔值
    # 必须在处理 int 之前处理 bool，因为在 Python 中 isinstance(True, int) 也是 True
    if isinstance(val, bool):
        return 1 if val else 0

    if isinstance(val, (list, dict)):
        try:
            return json.dumps(val, ensure_ascii=False)
        except:
            return str(val)

    # 其他情况转字符串 (防止 pymysql 无法识别某些特殊对象)
    # 如果是普通的 int/float，str() 后传给 pymysql 也是安全的
    return str(val)


def auto_create_table(conn):
    if not os.path.exists(JSON_FILE): return False
    with open(JSON_FILE, 'r', encoding='utf-8') as f:
        first_line = f.readline()
        if not first_line: return False
        try:
            sample_data = json.loads(first_line.strip())
        except:
            return False

    columns_sql = ["`id` INT AUTO_INCREMENT PRIMARY KEY"]
    for json_key, val in sample_data.items():
        db_field = JSON_TO_DB_MAPPING.get(json_key, json_key)
        db_type = infer_sql_type(val)
        columns_sql.append(f"`{db_field}` {db_type}")

    create_sql = f"CREATE TABLE IF NOT EXISTS `{TABLE_NAME}` ({', '.join(columns_sql)}) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"

    try:
        with conn.cursor() as cursor:
            cursor.execute(create_sql)
            conn.commit()
            print("✅ 表结构检测/创建完毕。")
            return True
    except Exception as e:
        print(f"❌ 建表失败: {e}")
        return False


# --- 3. 主程序 ---

def main():
    if not os.path.exists(JSON_FILE):
        print(f"❌ 文件不存在: {JSON_FILE}")
        return

    conn = get_connection()
    try:
        if not auto_create_table(conn):
            print("❌ 无法建立表结构")
            return

        with conn.cursor() as cursor:
            cursor.execute(f"DESCRIBE {TABLE_NAME}")
            db_columns = [col['Field'] for col in cursor.fetchall() if col['Field'] != 'id']

            col_str = ', '.join([f"`{c}`" for c in db_columns])
            val_placeholders = ', '.join(['%s'] * len(db_columns))
            sql = f"INSERT INTO {TABLE_NAME} ({col_str}) VALUES ({val_placeholders})"

            print(f"🚀 开始修正后的导入 (Batch: {BATCH_SIZE})...")
            start_time = time.time()

            batch_buffer = []
            total_success = 0

            with open(JSON_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue

                    try:
                        json_data = json.loads(line)
                        row_values = []

                        for col in db_columns:
                            json_key = FIELD_MAPPING.get(col, col)
                            val = clean_value_for_db(json_data.get(json_key))
                            row_values.append(val)

                        batch_buffer.append(row_values)

                        if len(batch_buffer) >= BATCH_SIZE:
                            cursor.executemany(sql, batch_buffer)
                            conn.commit()
                            total_success += len(batch_buffer)
                            print(f"   [进度] 已导入 {total_success} 条... (耗时: {time.time() - start_time:.2f}s)")
                            batch_buffer = []

                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        # 打印更详细的错误以便调试
                        print(f"⚠️ 错误详情: {e}")
                        # 如果需要看哪一行报错，可以取消下面注释，但会刷屏
                        # print(f"   错误数据: {line[:100]}...")

            if batch_buffer:
                cursor.executemany(sql, batch_buffer)
                conn.commit()
                total_success += len(batch_buffer)

            end_time = time.time()
            print("=" * 40)
            print(f"🏁 导入完成！")
            print(f"✅ 总计: {total_success}")
            print(f"⏱️ 耗时: {end_time - start_time:.2f} 秒")
            print("=" * 40)

    except Exception as e:
        print(f"⛔️ 发生错误: {e}")
    finally:
        conn.close()


if __name__ == '__main__':
    main()
