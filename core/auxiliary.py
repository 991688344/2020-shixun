import re
import queue
from difflib import SequenceMatcher
from core.requester import requester
from core.colors import red,green,end
from core.log import time
from urllib3.exceptions import ConnectTimeoutError
from core import regex


# 工具

def chambering(url,strike,payload = None,type = None):  # 提取url参数，按需替换payload  返回(url,参数) ('www.baidu.com', {'a': '1', 'bb': '22'})

    if "=" in url and "?" in url:
        data = url.split("?")[1].split("&")
        params_extractor = tuple((i.split('=')[0],i.split('=')[1]) for i in data)
        params = {i:j for i, j in params_extractor}
        url = url.split('?')[0]

        if strike and payload != None:
            if type == "SQLi":
                incursive = {key: "".join([params[key], payload]) for key in params.keys()}

            if type in ["XSS","file_inclusion","command_injection","ssrf"]:
                incursive = {key: payload for key in params.keys()}
            return (url,incursive)

        else:
            return (url,params)
    else:
        return (url,None)


def attack_check(original,attacked,type,payload = None):  # 对返回的页面进行差异度检测 相同返回False， 阈值0.95     可以继续改进此部分
    lower_limit = 0.95

    if type == "SQLi" or type == "command_injection":
        sequenceMatcher = SequenceMatcher(None)
        sequenceMatcher.set_seq1(original)
        sequenceMatcher.set_seq2(attacked)
        ratio = sequenceMatcher.quick_ratio()
        if ratio < lower_limit:
            return True
        else:
            return False
    elif type == "file_inclusion":      # 文件包含检测报错信息
        if regex.FI_ERROR_REGEX.search(attacked):

            return True
        else:
            return False
    elif type == "XSS":     # 如果是xss则检测返回页面中有没有payload
        if re.search(payload,attacked,re.I):
            return True
        else:
            return False


def check_live(proxy):  # 检测代理可不可用
    check_ip = "http://httpbin.org/ip"  # 类似于echo服务器
    ip = proxy[0] + ":" + proxy[1]
    try:
        response = requester(check_ip, data=None, timeout=3, GET=True, proxy=ip)
        if not response is None:
            if proxy[0] in response.text:
                return True
            return False
        return False
    except ConnectTimeoutError:
        return False


def get_proxy(proxy_queue):     # 从传入的代理队列中，提取出一个可用的代理
    proxy = proxy_queue.get()
    while not proxy_queue.empty():

        if check_live(proxy):
            print(f"{red}[!][{time}]{proxy[0]} is alive and testing with it !{end}")
            return proxy[0]
        else:
            print(f"{green}[!][{time}]{proxy[0]} is dead !{end}")
            proxy = proxy_queue.get()
    print(f"{red}[!][{time}] No more No available proxy{end}")
    return None



def vul_message(vul,url,payload):

    message = {
        "SQLi" : "SQL injection vulnerability has already been detected",
        "file_inclusion" : "File Inclusion vulnerability may exists",
        "command_injection" : "Command Injection vulnerability has already been detected",
        "ssrf" : "SSRF vulnerability has already been detected",
        "XSS"  : "XSS has already been detected"
    }

    message_box = f"-------------------------------------------\n" \
                  f"url : {url}\n"\
                  f"payload : {payload}\n" \
                  f"{message[vul]}\n" \
                  f"--------------------------------------------\n"

    return message_box



def convert_target(url):        # 处理各种url格式
    if url.lower().startswith("http"):
        return url
    elif url.lower().startswith("/"):
        return "http:/" + url
    else:
        return "http://"+url



def extract_domain(target):     # 提取域名
    if not target is None:
        if isinstance(target, list):
            domain = target[0].split(".")[1]
            return domain
        domain = target.split(".")[1]
        return domain
    return None



def file_handler(file):      # 从文件提取域名 返回队列
    domains = queue.Queue()
    with open(file,'r',buffering=1024) as handler:
        for i in handler:
            url = convert_target(i)
            domains.put(url)
    return domains


def error_check(page):      # 页面存活检测 不存在返回False
    if re.search("404",page):
        return False
    return True


def load_queue(subdomain):  # 从传入的参数中获取子域名，返回一个子域名队列
    subdomain_queue = queue.Queue()
    for i in subdomain:
        url = "http://"+i
        subdomain_queue.put(url)
    return subdomain_queue


if __name__ == '__main__':
    # chambering(url, strike, payload=None, type=None):
    url =  "https://plus.jd.com/indexf?low_system=appicon&flow_entrance=appicon11&flow_channel=pc"
    chambering(url,strike=False)
