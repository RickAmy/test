import asyncio
import os
import uuid

import websockets
import random
import json
import sys
from sparkai.log.logger import logger
from sparkai.v2.llm.llm import _SparkLLMClient


async def gen_client_id():
    return uuid.uuid4()

async def just_open_tcp(url):
    try:
        gen_id = await gen_client_id()
        async with websockets.connect(url) as websocket:
            await websocket.ping()
            print("Connected to")
            await asyncio.wait_for(gen_client_id(), 20)
            await websocket.close()
    except asyncio.TimeoutError:
        logger.info(f"Event wait_for Timed Out")


async def debug(task: int):
    logger.error(f"Active TCP websocket no.{task}")


if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv()
    c = _SparkLLMClient(
        app_id=os.environ["SPARKAI_APP_ID"],
        api_key=os.environ["SPARKAI_API_KEY"],
        api_secret=os.environ["SPARKAI_API_SECRET"],
        model_kwargs={}
    )

    clients = {}

    turn_server_url = "wss://spark-api.xf-yun.com/v3.5/chat"

    tcp_connections = 3
    tcp_active_tasks = []

    # increase sockets in asyncio loop
    if sys.platform == 'win32':
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)

    task = 0
    for _ in range(tcp_connections):
        task += 1
        tcp_active_tasks.append(just_open_tcp(_SparkLLMClient._create_url(
                    c.api_url,
                    c.api_key,
                    c.api_secret,

                ),))
        tcp_active_tasks.append(debug(task))

    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.wait(tcp_active_tasks))
    loop.close()
