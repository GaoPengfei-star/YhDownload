import re
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

BASE_URL1 = "http://woai789.zimiyy.com:8125/zhanui120.php"
CHANNELS = ["playarr", "playarr_wj", "playarr_hn", "playarr_sn", \
            "playarr_lz", "playarr_fs", "playarr_uk", "playarr_ff",\
            "playarr_kb", "playarr_bd", "playarr_wl"]

headers = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "\
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"
}

def download(url:str, method:str = "GET", *args, **kwargs) -> requests.Response:
    return requests.request(method=method.upper(), url=url, headers=headers, *args, **kwargs)

def concat_url(url:str) -> str:
    return "{}?url={}".format(BASE_URL1, url)

def parse_url(url:str) -> str:
    """解析剧集url值"""
    resp = download(url).text
    soup = BeautifulSoup(resp, "html.parser")
    for script in soup.find("html").find_all("script", recursive=False):
        if script.attrs.get("type") == "text/javascript" \
            and script.attrs.get("src"):
            return script.attrs.get("src")

def parse_url_list(url:str) -> list:
    """解析视频url列表数据"""
    res = {}
    resp = download(url).text
    def _parse(match):
        temp = {}
        for item in re.findall(match, resp):
            temp[item[0]] = item[1]
        return temp
    template = "{}\[(\d+?)\]=\"(.+?)\";"
    for channel in CHANNELS:
        res[channel] = _parse(template.format(channel))
    return res

def parse_video_url(url:str) -> str:
    """解析真实视频的url"""
    url = concat_url(url)
    resp = download(url).text
    script = BeautifulSoup(resp, "html.parser").find_all("script")[1]
    video_url = re.findall(r"=\"(.*)\"", script.text)[0]
    return video_url

def download_video(url:str, save_path:str):
    resp:requests.Response = download(url, stream=True)
    total_size = int(resp.headers.get("content-length", 0))
    progress_bar = tqdm(total=total_size, unit="iB", unit_scale=True)
    if resp.status_code == 200:
        with open(save_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024*1024):
                if chunk:
                    f.write(chunk)
                    progress_bar.update(len(chunk))
    progress_bar.close()

url = "http://www.yhdm98.com/acg/56741/162.html"
url = parse_url(url)
print(url)
res = parse_url_list(url)
print(res)
video_url = parse_video_url(res["playarr"]["162"].split(',')[0])
download_video(video_url, "videos/吞噬星空162.mp4")
