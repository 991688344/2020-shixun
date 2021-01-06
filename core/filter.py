import queue
import hashlib
from collections import Iterable
from core.auxiliary import convert_target
from core.regex import FILE_TYPE,URL_PATH


class Filter:

    def __init__(self,data,type,container):
        self.data = data
        self.type = type
        # self.md5 = hashlib.md5()
        self.contain_md5 = set()
        self.contain_target = queue.Queue()
        self.container = container



    @classmethod
    def filter(self,item,container):
        if FILE_TYPE.search(item) is None:      # 如果不是特殊文件链接，则将URL Hash值加入到container中 返回True
            md5 = hashlib.md5()
            md5.update(item.encode('utf-8'))
            if md5.hexdigest() not in container:
                container.add(md5.hexdigest())
                return True
            return False
        return False


    # @staticmethod
    def extractor(self,logger_type,target):         # 返回一个提取到的目标URL的队列
        try:
            if isinstance(self.data,Iterable):
                for items in self.data:
                    item = items.group()

                    if self.type == "proxy":
                        if self.filter(item,self.container):
                            self.contain_target.put(item)

                    elif self.type == "url":
                        filted_url = URL_PATH.sub("=",item)     # www.baidu.com/a/?b=
                        #print(f"[*] from filter.py line 47 : {filted_url}")
                        if self.filter(filted_url,self.container):  # 如果是原先没有的URL
                            url = convert_target(item)              # 处理一下URL格式
                            # # url = "http:/"+item
                            # logger = factory_logger(logger_type,target,"url")
                            # logger.info(url)
                            # print(f"{purple}[~][{time}] Collecting a target for testing : {url}{end}")
                            self.contain_target.put(url)            # 加入到目标URL中
                return self.contain_target
        except Exception as e:
            return e

