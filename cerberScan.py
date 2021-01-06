import time
import argparse
from core.banner import show_banner



show_banner()

time = time.strftime('%H:%M:%S')

parser = argparse.ArgumentParser()

parser.add_argument('-target', nargs='+', dest='target')
parser.add_argument('-thread', nargs='?', default=7, type=int, dest='thread')
parser.add_argument('-proxy', dest='proxy',action="store_true")
parser.add_argument('-waf',dest='waf',action="store_true")
parser.add_argument('-outfile',nargs='?',dest='outfile')
parser.add_argument('-cookie',nargs='?',dest='cookie')
parser.add_argument('-subdomains',dest='subdomains',action = "store_true")
parser.add_argument('-file', nargs='?', dest='file')
parser.add_argument('-detectMid', dest='detectmid', action='store_true')
parser.add_argument('-middleware', nargs='?', dest='middleware')
parser.add_argument("--account", nargs = '?',dest = 'account')
parser.add_argument("--password", nargs = '?', dest = 'password')



args = parser.parse_args()


waf = args.waf
file = args.file
target = args.target
cookie = args.cookie
detectmid = args.detectmid
middleware = args.middleware
subdomains = args.subdomains
proxy = args.proxy or None
threads = args.thread or 7
outfile = args.outfile
account = args.account
password = args.password


from core.proxies import Proxy
from strike.attack import Attack
from core.colors import red,green,end
from core.subdomain import subdomain
from core.middleware import detect_info
from strike.detect_waf import check_waf
from core.Quicksilver import quicksliver
from strike.Poc.poc_Attack import middleware_vulne
from core.auxiliary import convert_target,get_proxy,load_queue


file_= None
subdomain_queue = None
cookies = None
proxy_queue = None

if file:
    file_= str(file)

if cookie:
    cookies = cookies

if target:
    target = convert_target(target[0])



logger_type = "FileLogger" if outfile else "StreamLogger"


if subdomains:  # 设置检测子域名 字典 /data/DNSPod.txt
    sub = subdomain(target, file = "DNSPod.txt", logger_type = logger_type)
    subdomain_set = sub.execution()
    subdomain_queue = load_queue(subdomain_set)



if detectmid:   # 自动识别cms指纹，检测中间件漏洞
    middleware_info = detect_info(target,logger_type)
    middleware_vulne(url=target,logger_type = logger_type,middleware_info=middleware_info)


if middleware:  # 手动指定中间件类型
    vulne = middleware_vulne(target,logger_type,middleware_type = middleware)
    vulne.analyse()


if proxy:
    proxies = Proxy(target,logger_type)
    proxy_queue = proxies.executor()



if waf:     # 如果选择要检测WAF
    if proxy:   # 有代理则用代理
        proxy = get_proxy(proxy_queue)
        check_waf(target, logger_type, proxy = proxy)
    else:
        check_waf(target, logger_type)


#target = "http://test.com/SQL/sqli-labs/Less-1/?id=1"
module_attack = Attack(target,logger_type,cookie = cookies, subdomain_queue = subdomain_queue,proxy_queue = proxy_queue,file = file_)
execution = module_attack.execution
quicksliver(execution,threads)
print(f"{red}[!!][{time}] Vulnerability scan has finished !{end}")







