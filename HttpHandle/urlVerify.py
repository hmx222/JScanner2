import asyncio
import pandas as pd
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
import time
import os
from urllib.parse import urlparse, urljoin
import json

async def fetch_url_info(domain, path, browser, semaphore):
    """
    使用Playwright获取URL信息
    """
    async with semaphore:  # 限制并发数量
        try:
            # 清理域名和路径
            domain = str(domain).strip()
            path = str(path).strip() if pd.notna(path) else ''

            # 构建完整的URL
            if not domain.startswith(('http://', 'https://')):
                domain = f'https://{domain}'

            # 确保URL格式正确
            parsed_domain = urlparse(domain)
            if not parsed_domain.scheme:
                domain = f'https://{domain}'

            # 构建完整URL
            full_url = urljoin(domain.rstrip('/'), path.lstrip('/')) if path else domain

            print(f"Processing: {full_url}")

            # 创建新的浏览器上下文
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            )

            page = await context.new_page()

            # 设置超时
            response = None
            try:
                response = await page.goto(full_url, timeout=30000, wait_until='domcontentloaded')
            except PlaywrightTimeoutError:
                print(f"Timeout for {full_url}, trying to continue...")
                # 即使超时，也尝试获取页面信息
                pass
            except Exception as e:
                print(f"Error navigating to {full_url}: {str(e)}")
                await context.close()
                return {
                    'domain': domain,
                    'path': path,
                    'url': full_url,
                    'response_length': 0,
                    'content_type': 'error',
                    'title': str(e),
                    'status_code': 0,
                    'error': str(e)
                }

            # 获取页面标题
            title = ""
            try:
                title = await page.title()
            except Exception as e:
                print(f"Could not get title for {full_url}: {str(e)}")
                title = "No title available"

            # 获取响应信息
            response_length = 0
            content_type = 'unknown'
            status_code = 0

            if response:
                try:
                    # 获取响应体
                    response_body = await response.body()
                    response_length = len(response_body)

                    # 获取状态码
                    status_code = response.status

                    # 获取内容类型
                    content_type_header = response.headers.get('content-type', '').lower()

                    # 检测内容类型
                    if 'application/json' in content_type_header or full_url.lower().endswith('.json'):
                        content_type = 'json'
                    elif any(img_type in content_type_header for img_type in
                             ['image/', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg']):
                        content_type = 'image'
                    elif 'text/html' in content_type_header or full_url.lower().endswith(
                            ('.html', '.htm', '.php', '.asp', '.aspx')):
                        content_type = 'html'
                    elif 'text/plain' in content_type_header:
                        content_type = 'text'
                    elif 'application/xml' in content_type_header or 'text/xml' in content_type_header or full_url.lower().endswith(
                            '.xml'):
                        content_type = 'xml'
                    elif 'application/pdf' in content_type_header or full_url.lower().endswith('.pdf'):
                        content_type = 'pdf'
                    elif 'application/javascript' in content_type_header or full_url.lower().endswith(('.js', '.json')):
                        content_type = 'javascript'
                    else:
                        # 尝试分析内容
                        try:
                            decoded_content = response_body.decode('utf-8', errors='ignore').lower()
                            if decoded_content.strip().startswith(('{', '[')) and decoded_content.strip().endswith(
                                    ('}', ']')):
                                content_type = 'json'
                            elif '<html' in decoded_content or '<body' in decoded_content:
                                content_type = 'html'
                        except:
                            pass

                except Exception as e:
                    print(f"Error processing response for {full_url}: {str(e)}")

            # 关闭上下文
            await context.close()

            # 解析域名
            parsed_url = urlparse(full_url)
            domain_only = parsed_url.netloc

            return {
                'domain': domain_only,
                'path': path if path else '/',
                'url': full_url,
                'response_length': response_length,
                'content_type': content_type,
                'title': title,
                'status_code': status_code,
                'error': None
            }

        except Exception as e:
            print(f"Critical error for {domain}{path}: {str(e)}")
            return {
                'domain': str(domain),
                'path': str(path),
                'url': f"{domain}{path}",
                'response_length': 0,
                'content_type': 'critical_error',
                'title': str(e),
                'status_code': 0,
                'error': str(e)
            }


async def process_batch(domains, paths, max_concurrent=5):
    """
    处理一批URL，使用Playwright进行异步请求
    """
    results = []

    async with async_playwright() as p:
        # 启动浏览器
        browser = await p.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
        )

        # 创建信号量控制并发
        semaphore = asyncio.Semaphore(max_concurrent)

        # 创建任务列表
        tasks = []
        for domain, path in zip(domains, paths):
            if domain and str(domain).strip():  # 确保domain不为空
                task = fetch_url_info(domain, path, browser, semaphore)
                tasks.append(task)

        # 执行所有任务
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 关闭浏览器
        await browser.close()

    return results


def read_excel_data(file_path):
    """
    读取Excel文件的第三列和第四列数据，从第二行开始读取
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return [], []

        # 读取Excel文件，跳过第一行
        df = pd.read_excel(file_path, header=None, skiprows=1)

        print(f"Excel file shape: {df.shape}")

        # 检查是否有足够的列
        if df.shape[1] < 4:
            print(f"Excel file has only {df.shape[1]} columns, need at least 4 columns")
            return [], []

        # 提取第三列（索引2）和第四列（索引3）
        domains = df.iloc[:, 2].tolist()
        paths = df.iloc[:, 3].tolist() if df.shape[1] > 3 else [''] * len(domains)

        # 过滤掉空的domain
        filtered_domains = []
        filtered_paths = []
        for domain, path in zip(domains, paths):
            if pd.notna(domain) and str(domain).strip():
                filtered_domains.append(domain)
                filtered_paths.append(path if pd.notna(path) else '')

        print(f"Found {len(filtered_domains)} valid domains to process")
        return filtered_domains, filtered_paths

    except Exception as e:
        print(f"Error reading Excel file: {str(e)}")
        return [], []


def save_results_to_excel(results, output_file):
    """
    将结果保存到Excel文件
    """
    try:
        # 过滤掉异常结果
        valid_results = []
        for result in results:
            if isinstance(result, dict):
                valid_results.append(result)
            elif hasattr(result, '__dict__'):
                valid_results.append(vars(result))

        if not valid_results:
            print("No valid results to save")
            return False

        # 创建DataFrame
        df = pd.DataFrame(valid_results)

        # 选择需要的列，并按指定顺序排列
        columns_order = ['domain', 'path', 'url', 'response_length', 'content_type', 'title', 'status_code']
        if all(col in df.columns for col in columns_order):
            df = df[columns_order]

        # 确保输出目录存在
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        # 保存到Excel，使用utf-8编码
        df.to_excel(output_file, index=False, engine='openpyxl')

        print(f"Results saved to {output_file}")
        print(f"Total records saved: {len(df)}")

        return True

    except Exception as e:
        print(f"Error saving results to Excel: {str(e)}")
        return False


async def main():
    """
    主函数
    """
    start_time = time.time()

    # 配置文件路径
    input_file = "../Result/Result.xlsx"
    output_file = "../Result/Crawl_Results.xlsx"

    print("=" * 50)
    print("Starting URL crawler with Playwright")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print("=" * 50)

    # 读取Excel数据
    print("Reading Excel file...")
    domains, paths = read_excel_data(input_file)

    if not domains:
        print("No domains found to process. Exiting.")
        return

    print(f"Found {len(domains)} domains to process")

    # 处理URLs
    print("Starting async processing with Playwright...")
    results = await process_batch(domains, paths, max_concurrent=3)  # 控制并发数量

    # 保存结果
    print("Saving results to Excel...")
    success = save_results_to_excel(results, output_file)

    if success:
        total_time = time.time() - start_time
        print(f"✅ Processing completed successfully!")
        print(f"Total time: {total_time:.2f} seconds")
        print(f"Average time per URL: {total_time / len(domains):.2f} seconds")
    else:
        print("❌ Failed to save results")

    print("=" * 50)


if __name__ == "__main__":
    # 运行主函数
    asyncio.run(main())