from colorama import Fore, init

from fileHandler.fileIO import read, write_excel, remove_duplicates
from httpHandler.httpSend import send_http
from httpHandler.responseHandler import status, get_title, return_length
from jsHandler.pathScan import analysis_by_rex, height_scan, data_clean
from jsHandler.sensitiveInfoScan import find_all
from parse_args import parse_args

if __name__ == '__main__':
    # 初始化colorama，
    init()

    # get user args
    args = parse_args()

    # read url info
    if args.batch:
        url_list = read(args.batch)
    else:
        url_list = [args.url]

    for url in url_list:
        url_response_obj = send_http(url, "GET", args.header)
        if url_response_obj is None:
            continue
        first_analysis_result_list = data_clean(args.url,analysis_by_rex(url_response_obj.text))

        all_url_list = []
        if args.height > 0:
            # heigth scan
            height_scan_list = height_scan(first_analysis_result_list, "GET", args.header, args.height)
            # add two list into all_url_list
            all_url_list.extend(height_scan_list)
            all_url_list.extend(first_analysis_result_list)
        else:
            all_url_list.extend(first_analysis_result_list)
            # remove repeat url
        all_url_list = list(set(all_url_list))

        table_output = []
        sensitive_info_all_list = []



        # features scan
        for _url in all_url_list:
            try:
                url_response_obj = send_http(url, "GET", args.header)
                status_code = status(url_response_obj)
                if status_code in args.blackStatus:
                    continue
                title = get_title(url_response_obj)
                length = return_length(url_response_obj)
                sensitive_info_list = find_all(url_response_obj.text)
                for sensitive_info in sensitive_info_list:
                    print(Fore.RED + f"url:{_url}\n\tsensitive_info:{sensitive_info}"+Fore.RESET)

            except Exception as e:
                print(Fore.CYAN + f"{_url}\n\tERROR"+ Fore.RESET)
                table_output.append((url,"ERROR"))
            else:
                print(Fore.BLUE + f"url:{_url}\n\tstatus_code:{status_code}\n\ttitle:{title}\n\tlength:{length}" + Fore.RESET)
                table_output.append((url, status_code, title, length))

        if args.out:
            # 为了方便于辨识不同域名之间的文件
            name = args.url.replace(':','_')
            name = name.replace('/','_')
            # 写入Excel文件
            filename = write_excel(table_output,name)
            if args.redup:
                # 用户自定义去重的列
                remove_duplicates(filename,args.redup,name)


