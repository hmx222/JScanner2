import asyncio
import pandas as pd
import time
import os
from contextlib import asynccontextmanager
from urllib.parse import urlparse, urljoin
from playwright.async_api import async_playwright, Page, BrowserContext, TimeoutError as PlaywrightTimeoutError
from tqdm.asyncio import tqdm_asyncio

BLOCKED_RESOURCE_TYPES = {"image", "media", "font", "stylesheet"}
# 失败URL集合 参考你的写法
fail_url = set()

@asynccontextmanager
async def get_playwright_page(context: BrowserContext):
    """异步上下文管理器：创建和自动关闭页面【仅创建Tab，全局一个浏览器环境】- 照搬参考代码"""
    page = await context.new_page()
    try:
        yield page
    finally:
        try:
            await asyncio.wait_for(page.close(), timeout=3.0)
        except asyncio.TimeoutError:
            pass

async def fetch_url_info(page: Page, domain, path, progress: tqdm_asyncio):
    """
    核心爬取函数：保留你100%的业务逻辑 + 照搬参考代码的Playwright请求规范
    返回值结构和你原代码完全一致，无任何改动
    """
    try:
        domain = str(domain).strip()
        path = str(path).strip() if pd.notna(path) else ''

        if not domain.startswith(('http://', 'https://')):
            domain = f'https://{domain}'
        parsed_domain = urlparse(domain)
        if not parsed_domain.scheme:
            domain = f'https://{domain}'
        full_url = urljoin(domain.rstrip('/'), path.lstrip('/')) if path else domain

        print(f"Processing: {full_url}")

        await page.route("**/*", lambda route: route.abort()
            if route.request.resource_type in BLOCKED_RESOURCE_TYPES
            else route.continue_())

        response = None
        title = "No title available"
        response_length = 0
        content_type = 'unknown'
        status_code = 0
        response_body = b''

        try:
            response = await page.goto(full_url, timeout=3000, wait_until='domcontentloaded')
        except PlaywrightTimeoutError:
            print(f"Timeout for {full_url}, trying to continue...")
            fail_url.add(full_url)
            return {
                'domain': domain, 'path': path, 'url': full_url,
                'response_length': 0, 'content_type': 'error', 'title': 'Timeout',
                'status_code': 0, 'error': 'Timeout'
            }
        except Exception as e:
            fail_url.add(full_url)
            return {
                'domain': domain, 'path': path, 'url': full_url,
                'response_length': 0, 'content_type': 'error', 'title': str(e),
                'status_code': 0, 'error': str(e)
            }

        try:
            title = await page.title()
        except Exception:
            pass

        if response:
            try:
                status_code = response.status
                content_type_header = response.headers.get('content-type', '').lower()

                if 'application/json' in content_type_header or full_url.lower().endswith('.json'):
                    content_type = 'json'
                elif any(img_type in content_type_header for img_type in ['image/', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg']):
                    content_type = 'image'
                elif 'text/html' in content_type_header or full_url.lower().endswith(('.html', '.htm', '.php', '.asp', '.aspx')):
                    content_type = 'html'
                elif 'text/plain' in content_type_header:
                    content_type = 'text'
                elif 'application/xml' in content_type_header or 'text/xml' in content_type_header or full_url.lower().endswith('.xml'):
                    content_type = 'xml'
                elif 'application/pdf' in content_type_header or full_url.lower().endswith('.pdf'):
                    content_type = 'pdf'
                elif 'application/javascript' in content_type_header or full_url.lower().endswith('.js'):
                    content_type = 'javascript'
                else:
                    response_body = await response.body()
                    response_length = len(response_body)
                    if response_length < 1024 * 100:
                        try:
                            decoded_content = response_body.decode('utf-8', errors='ignore').lower()
                            if decoded_content.strip().startswith(('{', '[')) and decoded_content.strip().endswith(('}', ']')):
                                content_type = 'json'
                            elif '<html' in decoded_content or '<body' in decoded_content:
                                content_type = 'html'
                        except:
                            pass
                if response_length == 0:
                    response_length = len(response_body)
            except Exception as e:
                print(f"Error processing response for {full_url}: {str(e)}")

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
        err_info = str(e)
        print(f"Critical error for {domain}{path}: {err_info}")
        fail_url.add(f"{domain}{path}")
        return {
            'domain': str(domain),
            'path': str(path),
            'url': f"{domain}{path}",
            'response_length': 0,
            'content_type': 'critical_error',
            'title': err_info,
            'status_code': 0,
            'error': err_info
        }
    finally:
        progress.update(1)
        del response_body

async def process_batch(domains, paths, max_concurrent_tabs=5):
    """
    核心入口：完全照搬参考代码的 Playwright 启动/并发/任务封装逻辑
    没有TabPool、没有伪复用，纯参考代码的标准写法，资源占用极低
    """
    results = []
    progress = tqdm_asyncio(total=len(domains), desc="Process URLs", unit="url", ncols=100)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage"],
            slow_mo=0
        )
        global_context = await browser.new_context(
            ignore_https_errors=True,
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        )

        try:
            semaphore = asyncio.Semaphore(max_concurrent_tabs)
            async def bounded_fetch(domain, path):
                async with semaphore:
                    async with get_playwright_page(global_context) as page:
                        return await fetch_url_info(page, domain, path, progress)


            tasks = [
                bounded_fetch(domain, path)
                for domain, path in zip(domains, paths)
                if domain and str(domain).strip()
            ]
            results = await asyncio.gather(*tasks)

        finally:
            await global_context.close()
            await browser.close()
            progress.close()

    return results


def read_excel_data(file_path):
    try:
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return [], []
        df = pd.read_excel(file_path, header=None, skiprows=1)
        print(f"Excel file shape: {df.shape}")
        if df.shape[1] < 4:
            print(f"Excel file has only {df.shape[1]} columns, need at least 4 columns")
            return [], []
        domains = df.iloc[:, 2].tolist()
        paths = df.iloc[:, 3].tolist() if df.shape[1] > 3 else [''] * len(domains)
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
    try:
        valid_results = []
        for result in results:
            if isinstance(result, dict):
                valid_results.append(result)
            elif hasattr(result, '__dict__'):
                valid_results.append(vars(result))
        if not valid_results:
            print("No valid results to save")
            return False
        df = pd.DataFrame(valid_results)
        columns_order = ['domain', 'path', 'url', 'response_length', 'content_type', 'title', 'status_code']
        if all(col in df.columns for col in columns_order):
            df = df[columns_order]
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        df.to_excel(output_file, index=False, engine='openpyxl')
        print(f"Results saved to {output_file}")
        print(f"Total records saved: {len(df)}")
        print(f"Total failed URLs: {len(fail_url)}")
        return True
    except Exception as e:
        print(f"Error saving results to Excel: {str(e)}")
        return False

async def main():
    start_time = time.time()
    input_file = "../Result/Result.xlsx"
    output_file = "../Result/Crawl_Results.xlsx"
    print("=" * 50)
    print("Starting URL crawler | ✔ Reference Code Style ✔ Your Business Logic")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print("=" * 50)
    print("Reading Excel file...")
    domains, paths = read_excel_data(input_file)
    if not domains:
        print("No domains found to process. Exiting.")
        return
    print(f"Found {len(domains)} domains to process")
    print("Starting async processing...")
    # 128G服务器推荐并发数 15-20，丝滑不卡
    results = await process_batch(domains, paths, max_concurrent_tabs=10)
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
    asyncio.run(main())