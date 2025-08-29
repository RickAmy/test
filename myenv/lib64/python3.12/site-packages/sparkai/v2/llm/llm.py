#!/usr/bin/env python
# coding:utf-8
""" 
@author: nivic ybyang7
@license: Apache Licence 
@file: llm
@time: 2024/05/27
@contact: ybyang7@iflytek.com
@site:  
@software: PyCharm 

# code is far away from bugs with the god animal protecting
    I love animals. They taste delicious.
              ┏┓      ┏┓
            ┏┛┻━━━┛┻┓
            ┃      ☃      ┃
            ┃  ┳┛  ┗┳  ┃
            ┃      ┻      ┃
            ┗━┓      ┏━┛
                ┃      ┗━━━┓
                ┃  神兽保佑    ┣┓
                ┃　永无BUG！   ┏┛
                ┗┓┓┏━┳┓┏┛
                  ┃┫┫  ┃┫┫
                  ┗┻┛  ┗┻┛ 
"""
import base64
import hashlib
import hmac
import json
import os
import queue
import threading
from datetime import datetime
from queue import Queue
from time import mktime
from typing import Optional, Dict, List, Any, AsyncGenerator, Generator
from urllib.parse import urlparse, urlencode, urlunparse

import httpx
import websockets

from sparkai.errors import SparkAIConnectionError
from sparkai.llm.llm import prepare_user_agent
from sparkai.log.logger import logger
from sparkai.spark_proxy.spark_auth import format_date_time
from sparkai.v2.client.common.consts import IFLYTEK, DefaultDomain


#  Copyright (c) 2022. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
#  Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
#  Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
#  Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
#  Vestibulum commodo. Ut rhoncus gravida arcu.
import websocket


class _SparkLLMClient:
    """
    Use websocket-client to call the SparkLLM interface provided by Xfyun,
    which is the iFlyTek's open platform for AI capabilities
    """

    def __init__(
            self,
            app_id: str,
            api_key: str,
            api_secret: str,
            api_url: Optional[str] = None,
            spark_domain: Optional[str] = None,
            model_kwargs: Optional[dict] = None,
            user_agent: Optional[str] = None,
            provider=IFLYTEK,
            is_ws=True

    ):
        self.is_ws = is_ws
        if self.is_ws:
            self.client = websocket
        else:
            self.client = httpx.Client()

        self.spark_domain = spark_domain or DefaultDomain

        if api_url is None or api_url == "":
            self.api_url = self._adjust_api_by_domain("", self.spark_domain)
        else:
            self.api_url = self._adjust_api_by_domain(api_url, self.spark_domain)

        self.app_id = app_id
        self.api_key = api_key
        self.api_secret = api_secret
        self.model_kwargs = model_kwargs
        self.queue: Queue[Dict] = Queue()
        self.blocking_message = {"content": "", "role": "assistant"}
        self.api_key = api_key
        self.api_secret = api_secret
        self.user_agent = prepare_user_agent(user_agent)

    def _adjust_api_by_domain(self, url: str, domain: str) -> str:
        """
        Adjust the api base according the domain provided
        :param domain:
        :return:
        """
        host_map = {
            "generalv3.5": "wss://spark-api.xf-yun.com/v3.5/chat",
            "generalv3": "wss://spark-api.xf-yun.com/v3.1/chat",
            "generalv2": "wss://spark-api.xf-yun.com/v2.1/chat",
            "general": "wss://spark-api.xf-yun.com/v1.1/chat",
            "image": "wss://spark-api.cn-huabei-1.xf-yun.com/v2.1/image",
        }
        if domain == "":
            domain = DefaultDomain

        if domain not in host_map:
            logger.warning("not find the  domain： %s, maybe have problem!!!", domain)
            return url

        if url != "" and url != host_map[domain]:
            logger.warning("specified host not match the domain default host, using default domain: %s", domain)

        return host_map[domain]

    @staticmethod
    def _create_url(api_url: str, api_key: str, api_secret: str, method="GET") -> str:
        """
        Generate a request url with an api key and an api secret.
        """
        # generate timestamp by RFC1123
        date = format_date_time(mktime(datetime.now().timetuple()))
        encrypt_method = "hmac-sha256"
        # urlparse
        parsed_url = urlparse(api_url)
        host = parsed_url.netloc
        path = parsed_url.path

        signature_origin = f"host: {host}\ndate: {date}\n{method} {path} HTTP/1.1"

        # encrypt using hmac-sha256
        signature_sha = hmac.new(
            api_secret.encode("utf-8"),
            signature_origin.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()

        signature_sha_base64 = base64.b64encode(signature_sha).decode(encoding="utf-8")

        authorization_origin = f'api_key="{api_key}", algorithm="{encrypt_method}", \
        headers="host date request-line", signature="{signature_sha_base64}"'
        authorization = base64.b64encode(authorization_origin.encode("utf-8")).decode(
            encoding="utf-8"
        )

        # generate url
        params_dict = {"authorization": authorization, "date": date, "host": host}
        encoded_params = urlencode(params_dict)
        url = urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                encoded_params,
                parsed_url.fragment,
            )
        )
        return url

    def run(
            self,
            messages: List[Dict],
            user_id: str,
            model_kwargs: Optional[dict] = None,
            streaming: bool = False,
            function_definition: List[Dict] = []
    ) -> None:
        if self.is_ws:
            self.client.enableTrace(False)
            ws = self.client.WebSocketApp(
                _SparkLLMClient._create_url(
                    self.api_url,
                    self.api_key,
                    self.api_secret,

                ),
                on_message=self.on_message,
                on_error=self.on_error,
                on_close=self.on_close,
                on_open=self.on_open,
                header=self.user_agent
            )
            ws.function_definition = function_definition
            ws.messages = messages
            ws.user_id = user_id
            ws.model_kwargs = self.model_kwargs if model_kwargs is None else model_kwargs
            ws.streaming = streaming
            ws.run_forever()
        else:
            # HTTP logic
            result = self.request(messages)
            self.queue.put()

    async def arun(
            self,
            messages: List[Dict],
            user_id: str,
            model_kwargs: Optional[dict] = {},
            streaming: bool = False,
            function_definition: List[Dict] = [],
    ) -> threading.Thread:

        async with websockets.connect( _SparkLLMClient._create_url(
                    self.api_url,
                    self.api_key,
                    self.api_secret,

                )) as aws:
            await aws.send(json.dumps(
                self.gen_params(
                    messages=messages, user_id=user_id, model_kwargs=model_kwargs,
                    function_definition=function_definition
                )
            ))

        async for message in aws:
            print(message)


    def on_error(self, ws: Any, error: Optional[Any]) -> None:
        self.queue.put({"error": error, "error_code": -1})
        ws.close()

    def on_close(self, ws: Any, close_status_code: int, close_reason: str) -> None:
        logger.debug(
            {
                "log": {
                    "close_status_code": close_status_code,
                    "close_reason": close_reason,
                }
            }
        )
        self.queue.put({"done": True})

    def on_open(self, ws: Any) -> None:
        self.blocking_message = {"content": "", "role": "assistant"}
        data = json.dumps(
            self.gen_params(
                messages=ws.messages, user_id=ws.user_id, model_kwargs=ws.model_kwargs,
                function_definition=ws.function_definition
            )
        )
        ws.send(data)

    def on_message(self, ws: Any, message: str) -> None:
        data = json.loads(message)
        code = data["header"]["code"]
        logger.debug(f"sid: {data['header']['sid']}, code: {code}")
        if code != 0:
            self.queue.put(
                {"error": f"Error Code: {code}, Error: {data['header']['message']}", "error_code": code}
            )
            ws.close()
        else:
            choices = data["payload"]["choices"]
            status = choices["status"]
            content = choices["text"][0]["content"]
            function_call = choices['text'][0].get("function_call", "")
            if ws.streaming:
                self.queue.put({"data": choices["text"][0]})
            else:
                self.blocking_message["content"] += content

            if function_call:
                self.blocking_message["function_call"] = function_call

            if status == 2:
                #if  ws.streaming:
                self.queue.put({"data": self.blocking_message})
                usage_data = (
                    data.get("payload", {}).get("usage", {}).get("text", {})
                    if data
                    else {}
                )
                self.queue.put({"usage": usage_data})
                ws.close()

    def gen_params(
            self, messages: list, user_id: str, model_kwargs: Optional[dict] = None, function_definition: list = []
    ) -> dict:
        patch_id = model_kwargs.pop("patch_id", None)
        data: Dict = {
            "header": {"app_id": self.app_id, "uid": user_id},
            "parameter": {"chat": {"domain": self.spark_domain}},
            "payload": {"message": {"text": messages}},
        }
        if patch_id:
            data["header"]["patch_id"] = [patch_id]
        if len(function_definition) > 0:
            data["payload"]["functions"] = {}
            data["payload"]["functions"]["text"] = function_definition

        if model_kwargs:
            data["parameter"]["chat"].update(model_kwargs)

        logger.debug(f"Spark Request Parameters: {data}")
        return data

    async def a_subscribe(self, timeout: Optional[int] = 30) -> AsyncGenerator[Dict, None]:
        err_cnt = 0
        while True:
            try:
                content = self.queue.get(timeout=timeout)
            except queue.Empty as _:
                e = TimeoutError(
                    f"SparkLLMClient wait LLM api response timeout {timeout} seconds"
                )
                logger.error(e)
                err_cnt += 1
                if err_cnt >= 4:
                    raise e
                else:
                    continue
            if "error" in content:
                e = SparkAIConnectionError(error_code=content["error_code"], message=content["error"])
                err_cnt += 1
                raise e

            if "usage" in content:
                yield content
                continue
            if "done" in content:
                break
            if "data" not in content:
                break
            yield content

    def subscribe(self, timeout: Optional[int] = 30) -> Generator[Dict, None, None]:
        err_cnt = 0
        while True:
            try:
                content = self.queue.get(timeout=timeout)
            except queue.Empty as _:
                e = TimeoutError(
                    f"SparkLLMClient wait LLM api response timeout {timeout} seconds"
                )
                logger.error(e)
                err_cnt += 1
                if err_cnt >= 4:
                    raise e
                else:
                    continue
            if "error" in content:
                e = SparkAIConnectionError(error_code=content["error_code"], message=content["error"])
                err_cnt += 1
                raise e

            if "usage" in content:
                yield content
                continue
            # continue
            if "done" in content:
                break
            if "data" not in content:
                break
            yield content

    # def request(self, messages):
    #     resp = self.client.get('')
    #     result = resp.json()
    #     # print(result)
    #     assert result["code"] == 300
    #     return result

if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv()
    c = _SparkLLMClient(
        app_id=os.environ["SPARKAI_APP_ID"],
        api_key=os.environ["SPARKAI_API_KEY"],
        api_secret=os.environ["SPARKAI_API_SECRET"],
        model_kwargs={}
    )
    messages = [{'role': 'user',
                 'content': "卧槽"}]
    import asyncio
    asyncio.run(c.arun(
        messages, user_id="1"
    ))
