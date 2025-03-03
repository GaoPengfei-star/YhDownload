import os
import time
import json
import asyncio
import shutil
import logging
from argparse import ArgumentParser   # 命令行参数解析
from typing import Literal, List, Tuple      # 类型提示
from uuid import uuid4          # 生成uuid
from dataclasses import dataclass # 数据类
from enum import Enum           # 枚举
from urllib.parse import urljoin # 合并url
from concurrent.futures import ThreadPoolExecutor, as_completed # 线程池

from Crypto.Cipher import AES   # 加密算法
from Crypto.Util.Padding import pad, unpad # 填充算法

import m3u8                     # 解析m3u8文件
import aiofiles                 # 异步文件操作
import aiohttp                  # 异步http请求
import requests                 # 同步http请求
from bs4 import BeautifulSoup   # 解析html文件
from tqdm import tqdm           # 进度条显示
from loguru import logger      # 日志模块
from tqdm.asyncio import tqdm_asyncio # 异步进度条显示
from tenacity import retry, stop_after_attempt, wait_fixed # 重试机制

"""
下载樱花动漫网站的视频数据：https://www.yinghuadongman.one
步骤：
1. 请求页面，获取第一个m3u8文件,解析获取第二个m3u8文件链接
2. 根据第二个m3u8文件请求ts文件列表，下载ts文件
3. 下载所有ts文件，合并为mp4文件

支持断点续传、多线程下载、单线程下载、进度条显示、日志记录、代理、日志debug、超时重试功能
支持命令行操作

"""
RETRY_COUNT = 3 # 重试次数
WAIT_TIME = 1 # 重试间隔

# 设置同时下载的最大文件数量
CONSURRENT_NUM = 2
semaphore = asyncio.Semaphore(CONSURRENT_NUM)

class TaskStatus(Enum):
    """任务状态"""
    PENDING = 0
    RUNNING = 1
    FINISHED = 2
    FAILED = 3

# 任务类
@dataclass
class Task:
    # 剧集名
    name: str
    # ID
    id: str
    # url
    url: str
    # 状态
    status: TaskStatus
    # 数据
    data: bytearray
    # 缓存路径
    cache_dir: str
    key: bytes
    iv: bytes

    def __init__(self, url:str, name:str='', id:str='', 
                 cache_dir:str='', key:bytes=b'', iv:bytes=b''):
        self.id = id
        self.url = url
        self.name = name
        self.status = TaskStatus.PENDING
        self.data = bytearray()
        self.cache_dir = cache_dir
        self.key = key
        self.iv = iv

class YHDonwnloader:
    def __init__(self, mode:Literal["sync", "async", "thread", "thread_async"]="sync", save_dir:str="./", 
                 keep_cache=False, proxy=None, debug:bool=False):
        self.mode = mode
        self.heders = {
            'accept': '*/*',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0'
        }
        self.proxy = proxy
        self.debug = debug
        # 检查保存目录是否存在
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)
        # 设置缓存目录
        self.cache_dir = os.path.join(save_dir, ".cache")
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.save_dir = save_dir
        self.keep_cache = keep_cache
        self.logger = logger
    
    def _prase_html(self, html:str) -> Tuple[str, str, int]:
        """解析html文件获取m3u8文件链接
        Args:
            html (str): html文件内容
        """
        # 解析html文本
        parser = BeautifulSoup(html, 'html.parser')
        # 解析剧集名
        name = parser.select_one("meta[name='keywords']").attrs["content"].split(",")[0]
        name = name.strip().replace(" ", "")
        # 选择数据
        txt = parser.select_one(".player").select_one("script").text.split("=", 1)[1]
        data = json.loads(txt)
        # 解析剧集的id
        nid = data["nid"]
        # 获取m3u8文件链接
        m3u8_url = data["url"]
        return m3u8_url, name, nid
    
    def _parse_m3u8(self, m3u8_txt:str, base_url:str="") -> List:
        """解析m3u8文件，获取ts文件列表
        Args:
            m3u8_txt (str): ts文件列表
        """
        key, iv = b"", b""
        #解析ts文件
        if "#EXT-X-DISCONTINUITY" in m3u8_txt:
            m3u8_txt = m3u8_txt.split("#EXT-X-DISCONTINUITY", 1)[0]
        m3u8_obj = m3u8.loads(m3u8_txt)
        #判断是否需要加解密
        if m3u8_obj.keys:
            #设置全局的key和iv
            if m3u8_obj.keys[0].uri and base_url:
                task = Task(urljoin(base_url + "/", m3u8_obj.keys[0].uri))
                self._sync_req(task)
                if task.status == TaskStatus.FINISHED:
                    key = task.data
                    if m3u8_obj.keys[0].iv:
                        iv = bytes.fromhex(m3u8_obj.keys[0].iv[2:])
        # 获取所有的ts文件链接
        ts_urls = []
        start_tag = m3u8_obj.keys[0].uri.rsplit("/", 1)[0] if not iv else "/"
        for item in m3u8_obj.segments:
            if item.uri.startswith("http"):
                ts_urls.append(item.uri)
            elif item.uri.startswith(start_tag):
                ts_urls.append(urljoin(base_url, item.uri))
        return ts_urls, key, iv

    def _check_m3u8(self, task:Task, base_url:str):
        """检查m3u8文件是否有效
        Args:
            task (Task): 任务对象
        """
        m3u8_txt = task.data.decode()
        m3u8_obj = m3u8.loads(m3u8_txt)
        #判断是否有keys
        if not bool(m3u8_obj.keys):
            #没有则需要再次请求m3u8文件获取key
            task.url = urljoin(base_url.rsplit("/", 2)[0] + "/", m3u8_obj.data["playlists"][0]["uri"])
            self._sync_req(task)
            base_url = base_url.rsplit("/", 2)[0]
        return base_url

    def _get_ts_url(self, url:str) -> Tuple[List, str, int, bytes, bytes]:
        """获取所有ts文件链接
        Args:
            url (str): 视频的链接
        Returns:
            List[str]: ts文件列表
            str: 剧集名
            int: 剧集id
        """
        #封装任务类
        task = Task(url)
        #请求视频页面
        self._sync_req(task)
        if task.status == TaskStatus.FINISHED:
            #解析m3u8文件链接
            m3u8_url, name, nid = self._prase_html(task.data.decode())
            #修改缓存地址
            cache_dir = os.path.join(self.cache_dir + "/", m3u8_url.rsplit("/", 2)[1])
            #设置base_url
            base_url = m3u8_url.rsplit("/", 1)[0]
            #请求m3u8文件
            task = Task(m3u8_url)
            self._sync_req(task)
            #检查m3u8文件是否有效
            base_url = self._check_m3u8(task, base_url)
            #请求m3u8文件
            if task.status == TaskStatus.FINISHED:
                #解析m3u8文件
                ts_urls, key, iv = self._parse_m3u8(task.data.decode(), base_url)
                return ts_urls, name, nid, cache_dir, key, iv
        return [], "", 0, self.cache_dir, b"", b""

    def get_ts(self, url:str) -> Tuple[List, str, int, bytes, bytes]:
        """获取对应的ts文件列表
        Args:
            url (str): 视频的链接
        Returns:
            List[str]: ts文件列表
            str: 剧集名
            int: 剧集id
        """
        return self._get_ts_url(url)

    @retry(stop=stop_after_attempt(RETRY_COUNT), wait=wait_fixed(WAIT_TIME))
    def _sync_req(self, task:Task, method:Literal["GET", "POST"]="GET"):
        """同步请求
        Args:
            task (Task): 任务对象
            method (Literal[&quot;GET&quot;, &quot;POST&quot;], optional): 请求方法. Defaults to "GET".
        Returns:
            str: 返回响应的文本内容
        """
        # 修改任务装填为运行
        task.status = TaskStatus.RUNNING  
        # 请求数据
        resp = requests.request(method, url=task.url, headers=self.heders, proxies=self.proxy)
        # 处理响应
        if resp.status_code == 200:
            task.status = TaskStatus.FINISHED
        else:
            task.status = TaskStatus.FAILED
        # 设置响应数据
        task.data = resp.content
        return task    

    def _decrypt_ts(self, data:bytes, key:bytes, iv:bytes) -> bytes:
        """解密ts文件
        Args:
            data (bytes): 加密的ts文件
        Returns:
            bytes: 解密后的ts文件
        """
        if key and not iv:
            aes = AES.new(key, AES.MODE_ECB)
            decrypted_data = aes.decrypt(data)
        elif key and iv:
            aes = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(aes.decrypt(data), AES.block_size)
        return decrypted_data

    @retry(stop=stop_after_attempt(RETRY_COUNT), wait=wait_fixed(WAIT_TIME))
    async def _async_req(self, task:Task, session:aiohttp.ClientSession, 
                         method:Literal["GET", "POST"]="GET"):
        """异步请求
        Args:
            task (Task): 任务对象
            method (Literal[&quot;GET&quot;, &quot;POST&quot;], optional): 请求方法. Defaults to "GET".
        Returns:
            str: 返回响应的文本内容
        """
        # 修改任务状态
        task.status = TaskStatus.RUNNING
        # 请求数据
        async with session.request(method,url=task.url) as resp:
            # 处理响应
            if resp.status == 200:
                task.status = TaskStatus.FINISHED
            else:
                task.status = TaskStatus.FAILED
            # 设置响应数据
            task.data = await resp.content.read()
        return task

    async def _async_download(self, tasks:List[Task]):
        """下载所有的ts文件
        Args:
            tasks (List[Task]): 任务列表
        """
        async with semaphore:
            # 异步请求
            async with aiohttp.ClientSession(headers=self.heders, proxy=self.proxy) as session:
                async_tasks = []
                for task in tasks:
                    # 检查任务状态
                    if task.status == TaskStatus.PENDING:
                        async_tasks.append(asyncio.create_task(self._async_req(task, session)))
                
                # 等待异步任务完成  
                for fut in tqdm_asyncio.as_completed(async_tasks):
                    # 获取异步任务的结果
                    task = await fut
                    # 处理响应
                    if task.status == TaskStatus.FINISHED:
                        if task.key:
                            task.data = self._decrypt_ts(task.data, task.key, task.iv)
                        # 缓存数据
                        async with aiofiles.open(os.path.join(task.cache_dir, task.url.rsplit("/", 1)[-1]), "wb") as f:
                            await f.write(task.data)

        # 检查所有任务的执行状态
        result = self._check_all_task_status(tasks)
        if not result:
            # 下载失败，重新下载
            await self._async_download(tasks)

    def _save_data(self, path:str, data:bytes):
        """保存数据到指定文件
        Args:
            path (str): 文件路径
            data (bytes): 数据
        """
        with open(path, "wb") as f:
            f.write(data)

    def _thread_download(self, tasks:List[Task]):
        """使用多线程下载
        Args:
            tasks (List[Task]): 任务列表
        """
        with ThreadPoolExecutor(max_workers=CONSURRENT_NUM) as executor:
            futs = []
            for task in tasks:
                # 检查任务状态
                if task.status == TaskStatus.PENDING:
                    # 执行下载请求
                    fut = executor.submit(self._sync_req, task)
                    futs.append(fut)
            
            if futs:
                with tqdm(total=len(futs)) as pbar:
                    for fut in as_completed(futs):
                        task = fut.result()
                        # 等待线程任务完成
                        if not task or task.status == TaskStatus.FINISHED  or task.status == TaskStatus.FAILED:
                            # 解密数据
                            pbar.update(1)
                        # 处理响应
                        if task.status == TaskStatus.FINISHED:
                            # 解密数据
                            if task.key:
                                task.data = self._decrypt_ts(task.data, task.key, task.iv)
                            # 在主线程中缓存数据 
                            self._save_data(os.path.join(task.cache_dir, task.url.rsplit("/", 1)[-1]), task.data)
                                    
        # 检查所有任务的执行状态
        result = self._check_all_task_status(tasks)
        if not result:
            # 下载失败，重新下载
            self._thread_download(tasks)

    def _sync_download(self, tasks:List[Task]):
        """同步下载所有的ts文件
        Args:
            tasks (List[Task]): 任务列表
        """
        # 显示进度条
        for task in tqdm(tasks, desc="Downloading", total=len(tasks)):
            # 请求数据
            if task.status == TaskStatus.PENDING:
                # 执行下载请求
                self._sync_req(task)
                # 处理响应
                if task.status == TaskStatus.FINISHED:
                    # 解密数据
                    if task.key:
                        task.data = self._decrypt_ts(task.data, task.key, task.iv)
                    # 缓存数据
                    with open(os.path.join(task.cache_dir, task.url.rsplit("/", 1)[-1]), "wb") as f:
                        f.write(task.data)
        
        # 检查所有任务的执行状态
        result = self._check_all_task_status(tasks)
        if not result:
            # 下载失败，重新下载
            self._sync_main(tasks)

    async def _async_main(self, urls:list[str]) -> List[Task]:
        """异步下载视频的主函数
        Args:
            url (str): 视频的链接
        """
        # 遍历所有的url
        for url in urls:
            # 获取ts文件列表
            ts_urls, name, nid, cache_dir, key, iv = self._get_ts_url(url)
            self._log_info("获取{}第{}集的ts文件数量:{}".format(name, nid, len(ts_urls)), logging.DEBUG)
            save_path = os.path.join(self.save_dir, "{}-第{}集.mp4".format(name, nid))
            # 检查是否已经存在
            if not self._check_file_exist(save_path):
                self._log_info("开始下载: {} 第{}集".format(name, nid))
                # 检查缓存文件是否存在
                if not os.path.exists(cache_dir):
                    os.makedirs(cache_dir)
                # 构建任务列表
                tasks = [Task(item, name, nid, cache_dir, key, iv) for item in ts_urls]
                # 检查任务状态
                self._check_task_status(tasks)
                # 下载ts文件
                await self._async_download(tasks)
                # 合并ts文件
                self._merge_ts(tasks)
            else:
                self._log_info("文件已存在: {}".format(save_path))
    
    def _check_file_exist(self, path:str) -> bool:
        """检查文件是否存在
        Args:
            path (str): 文件路径
        Returns:
            bool: 文件是否存在
        """
        return os.path.exists(path)

    def _sync_main(self, urls:list[str]) -> List[Task]:
        """同步下载视频的主函数
        Args:
            url (str): 视频的链接
        Returns:
            List[Task]: 任务列表
        """
        for url in urls:
            # 获取ts文件列表
            ts_urls, name, nid, cache_dir, key, iv = self._get_ts_url(url)
            save_path = os.path.join(self.save_dir, "{}-第{}集.mp4".format(name, nid))
            self._log_info("获取{}第{}集的ts文件数量:{}".format(name, nid, len(ts_urls)), logging.DEBUG)
            if not self._check_file_exist(save_path):
                self._log_info("开始下载: {} 第{}集".format(name, nid))
                # 检查缓存文件是否存在
                if not os.path.exists(cache_dir):
                    os.makedirs(cache_dir)
                # 下载ts文件
                tasks = [Task(item, name, nid, cache_dir, key, iv) for item in ts_urls]
                # 检查任务状态
                self._check_task_status(tasks)
                # 下载ts文件
                if self.mode == "thread":
                    self._thread_download(tasks)
                elif self.mode == "sync":
                    self._sync_download(tasks)
                # 合并ts文件
                self._merge_ts(tasks)
            else:
                self._log_info("文件已存在: {}".format(save_path))
        
    def _check_task_status(self, tasks:List[Task]):
        """检查任务状态
        Args:
            tasks (List[Task]): 任务列表
        """
        # 读取缓存目录中的数据
        cache_dir = tasks[0].cache_dir
        _, _, files = next(os.walk(cache_dir))
        # 查看指定任务数据是否已经存在
        for task in tasks:
            if task.url.rsplit("/", 1)[-1] in files:
                # 修改任务状态
                task.status = TaskStatus.FINISHED

    def _check_all_task_status(self, tasks:List[Task]) -> bool:
        """检查所有任务的执行状态
        Args:
            tasks (List[Task]): 任务列表
        """
        # 检查所有任务的执行状态
        return all([task.status == TaskStatus.FINISHED for task in tasks])

    def _merge_ts(self, tasks:List[Task]):
        """合并ts文件
        Args:
            tasks (List[Task]): 任务列表
        """
        # 读取缓存目录中的数据
        cache_dir = tasks[0].cache_dir
        name, nid = tasks[0].name, tasks[0].id
        root, _, files = next(os.walk(cache_dir))
        # 查看所有任务数据文件是否存在
        # 获取任务数据保存路径
        paths = [task.url.rsplit("/", 1)[-1] for task in tasks if task.status == TaskStatus.FINISHED]

        if all([path in files for path in paths]):        
            # 按照顺序保存ts文件到文件
            all_ts_path = os.path.join(cache_dir, "video.txt")
            with open(all_ts_path, "w") as f:
                for path in paths:
                    f.write("file '{}'\n".format(os.path.abspath(os.path.join(root + '/', path))))
            
            save_path = os.path.join(self.save_dir, "{}-第{}集.mp4".format(name, nid))
            if not os.path.exists(save_path):
                # 使用ffmpeg合并所有ts文件
                os.system("ffmpeg -f concat -safe 0 -i {} -c copy {}".format(
                    all_ts_path, 
                    save_path))
            # 是否删除缓存目录中的数据, 成功合成后删除缓存目录
            if not self.keep_cache and os.path.exists(save_path):
                if os.path.exists(all_ts_path):
                    os.remove(all_ts_path)
                if os.path.exists(cache_dir):
                    # 删除缓存文件
                    shutil.rmtree(cache_dir)

    def _thread_async(self, urls:List[str], loop:asyncio.AbstractEventLoop=None):
        """多线程和协程下载视频
        Args:
            urls (List[str]): 视频的链接列表
        """
        if loop:
            loop.run_until_complete(self._async_main(urls))
            loop.close()

    def _thread_async_main(self, urls:List[str]):
        """多线程和协程下载视频
        Args:
            url (List[str]): 视频的链接列表
        """
        # 多线程下载视频
        with ThreadPoolExecutor(max_workers=CONSURRENT_NUM) as executor:
            # 异步下载视频
            futs = []
            step = max(1, len(urls) // CONSURRENT_NUM)
            for i in range(0, len(urls), step):
                sub_urls = urls[i:i+step]
                loop = asyncio.new_event_loop()
                futs.append(executor.submit(self._thread_async, sub_urls, loop))
            # 等待所有线程完成
            for fut in as_completed(futs):
                res = fut.result()

    def _log_info(self, msg:str, level:int=logging.INFO):
        """打印日志信息
        Args:
            msg (str): 日志信息
        """
        if self.debug:
            if level == logging.INFO:
                self.logger.info(msg)
            elif level == logging.ERROR:
                self.logger.error(msg)
            elif level == logging.WARNING:
                self.logger.warning(msg)
            elif level == logging.DEBUG:
                self.logger.debug(msg)  

    def run(self, urls:list[str]):
        """运行入口
        """
        if self.mode == "sync" or self.mode == "thread":
            self._sync_main(urls)
        elif self.mode == "async":
            asyncio.run(self._async_main(urls))
        elif self.mode == "thread_async":
            self._thread_async_main(urls)
        # 删除缓存目录
        shutil.rmtree(self.cache_dir)

def main():
    parser = ArgumentParser(description="樱花动漫视频下载")
    parser.add_argument("-u", "--url", type=str, nargs="+", help="视频的链接")
    parser.add_argument("-m", "--mode", type=str, default="thread", choices=["sync", "async", "thread", "thread_async"], help="下载模式")
    parser.add_argument("-sd", "--save_dir", type=str, default=".", help="视频保存目录")
    parser.add_argument("-kc", "--keep_cache", action="store_true", help="是否保留缓存文件")
    parser.add_argument("-d", "--debug", action="store_true", help="是否开启调试模式")
    parser.add_argument("-p", "--proxy", type=str, default=None, help="代理地址")
    args = parser.parse_args()
    downloader = YHDonwnloader(mode=args.mode, save_dir=args.save_dir, keep_cache=args.keep_cache, debug=args.debug)
    downloader.run(args.url)

if __name__ == "__main__":
    main()
