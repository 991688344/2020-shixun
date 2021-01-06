import time
import asyncio
import aiodns
from core.colors import blue_green,end
from core.log import factory_logger,time



class subdomain:
# 字典+DNS爆破子域名  返回subdomains集合
    def __init__(self,target,file,logger_type):
        self.file = file
        self.time = time
        self.subdomains = set()
        self.file_loader = asyncio.Queue()
        self.loop = asyncio.get_event_loop()
        self.domain = target.split(".", target.count(".") - 1)[-1]
        self.resolver = aiodns.DNSResolver(timeout=3, loop=self.loop)
        self.logger = factory_logger(logger_type, target, 'subdomain')


    def load_file(self):    # file_loader中添加子域名字典 /data/NDSPod.txt
        with open(f"data/{self.file}", "r", buffering=1024) as handle:
            for count in handle:
                prefix = handle.readline()
                subdomain = "".join([prefix.rstrip(), ".", self.domain])
                self.file_loader.put_nowait(subdomain)



    async def query(self):  # file_loader读取子域名，判断子域名有A类DNS记录则加入到 subdomains中
        while True:
            domain = await self.file_loader.get()   # 协程请求子域名
            try:
                if await self.resolver.query(domain, 'A'):  # 查询子域名 A类DNS记录（IP地址） 如果存在A类记录
                    self.logger.info(f"{domain}")
                    # self.logger2.info("query")
                    self.subdomains.add(domain)
                    # self.subdomains
            except aiodns.error.DNSError:
                pass

            finally:
                self.file_loader.task_done()    # 发送任务完成信号 queue-1


    async def process(self):

        tasks = [asyncio.create_task(self.query()) for _ in range(100)]     # 创建DNS查询协程 加入到任务循环中
        await self.file_loader.join()   # 等待file_loader中所有子域名都完成

        for task in tasks:  # 取消任务
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)    # 得到所有任务执行结果，无返回结果



    def execution(self):
        try:
            self.load_file()    # 加载子域名字典
            self.loop.run_until_complete(self.process())
            # self.logger_count = factory_logger(logger_type,target, 'subdomain_count')
            # self.logger_count.info(f"{len(self.subdomains)}")
            print(f'{blue_green}[!][{self.time}] A total of {len(self.subdomains)} subdomains have been collected !{end}')
            return self.subdomains
        except Exception as e:
            return e

