import queue
from core import regex
from core.filter import Filter
from core.requester import requester
from core.assault_pre import assault_pre
from core.log import time,factory_logger
from core.colors import red,blue_green,end
from core.auxiliary import chambering,attack_check,extract_domain,vul_message,file_handler,error_check,get_proxy



class Attack:

    def __init__(self,target,logger_type,cookie = None,subdomain_queue = None,proxy_queue = None,file = None):
        self.file = file
        self.proxy = None
        self.target = target
        self.cookie = cookie
        self.requests_seen = set()
        self.filter_ = Filter.filter
        self.logger_type = logger_type
        self.proxy_queue = proxy_queue
        self.target_url = queue.Queue()
        self.Attack_target = queue.Queue()
        self.target_domain = queue.Queue()
        self.domain = extract_domain(target)
        self.subdomains_queue = subdomain_queue
        self.logger = factory_logger(logger_type,target,"vulnerable")



    def url_extrator(self,response):    # 从href提取URL队列并加入到target_url中
        try:
            iter_url = regex.URL_REGEX.finditer(response)   # href="/b/a"
            filter_data = Filter(iter_url,"url",self.requests_seen) # 初始化过滤器
            target_queue = filter_data.extractor(self.logger_type,self.target)  # 提取到除特殊文件之外的URL队列
            self.target_url.put(target_queue)
        except Exception:
            pass



    def initis(self):       # 访问原始URL，爬取页面URL加入到目标URL
        url, data = chambering(self.target, strike=False)
        received = requester(url, data, GET=True)
        self.url_extrator(received.text)



    def initialis_subdomain(self):      # 从子域名队列中提取URL加入到目标
        try:
            while not self.subdomains_queue.empty():
                target = self.subdomains_queue.get()
                url, data = chambering(target, strike = False)
                received = requester(url, data, GET=True, timeout = 5)
                if not received is None:
                    self.url_extrator(received.text)
                else:
                    pass
        except Exception:
            pass


    def initislis_file(self):       # 从文件中提取域名中的URL加入到目标
        try:
            domains = file_handler(self.file)
            while not domains.empty():
                target = domains.get()
                url, data = chambering(target, strike = False)
                received = requester(url, data, GET=True)
                if not received is None:
                    self.url_extrator(received.text)
                else:
                    pass
        except Exception:
            pass



    def execution(self):        # 执行攻击
        try:
            if not self.file is None:       # 加载目标
                self.initislis_file()
            if not self.subdomains_queue is None:
                self.initialis_subdomain()
            if not self.target is None:
                self.initis()

            while not self.target_url.empty():
                target = self.target_url.get()      #
                # strike_pre = assault_pre()
                # strike_pre.payload_provide()

                while not target.empty():
                    original = target.get()
                    # url = regex.URL_PATH.sub("=", original)
                    """and self.filter_(url,self.requests_seen)"""

                    if self.domain in original:     # 目标属于传入的域名 baidu.com/a/b/text?a=2&b=21 属于 baidu.com
                        url, data = chambering(original,strike = False)
                        received_ = requester(url,data,GET = True,cookie = self.cookie,proxy = self.proxy)
                        if not received_ is None and received_.status_code == 403:  # 如果代理被ban则切换代理
                            if not self.proxy_queue is None and not self.proxy_queue.empty():
                                self.proxy = get_proxy(self.proxy_queue)
                        print(f"{blue_green}[+][{time}] Vulnerability scanning is being performed on {original}{end}")
                        if not received_ is None:
                            self.url_extrator(received_.text)   # 从这个域名中继续提取URL加入到目标中
                        else:
                            pass

                    if "=" in original:     # 如果有参数
                        url, data = chambering(original, strike=False)
                        strike_pre = assault_pre()      # 实例化payload预处理类
                        strike_pre.payload_provide()    # 加载payload
                        received = requester(url, data, GET=True,cookie = self.cookie,proxy = self.proxy)

                        for vul_type, category in strike_pre.get_payload_category().items():
                            for count in range(category[1].qsize()):    # category[1] 为payload队列
                                payload = category[0]()                 # category[0] 为遍历攻击队列的方法
                                url, data = chambering(original,strike = True,payload=payload,type = vul_type)

                                if vul_type in ["SQLi","XSS","file_inclusion","command_injection","ssrf"]:
                                    Poisoned = requester(url,data,GET = True,cookie = self.cookie,proxy = self.proxy)

                                    if not Poisoned is None and Poisoned.status_code < 400: # 如果攻击有响应
                                        if error_check(Poisoned.text):  # 如果页面存在
                                            if attack_check(received.text,Poisoned.text,vul_type,payload): # 如果页面不同
                                                message = vul_message(vul_type,original,payload)    # 输出攻击完成
                                                self.logger.critical(message)
                                        else:
                                            pass
                                    else:
                                        pass

        except Exception:
            pass




