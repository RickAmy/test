#!/usr/bin/env python
# coding:utf-8
""" 
@author: nivic ybyang7
@license: Apache Licence 
@file: constants
@time: 2024/03/22
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

#  Copyright (c) 2022. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
#  Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
#  Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
#  Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
#  Vestibulum commodo. Ut rhoncus gravida arcu.

import os
"""
Global constants.
"""

from enum import IntEnum

CONTROLLER_HEART_BEAT_EXPIRATION = int(
    os.getenv("SPARKAI_CONTROLLER_HEART_BEAT_EXPIRATION", 90)
)

WORKER_HEART_BEAT_INTERVAL = int(os.getenv("SPARKAI_WORKER_HEART_BEAT_INTERVAL", 45))
WORKER_API_TIMEOUT = int(os.getenv("SPARKAI_WORKER_API_TIMEOUT", 100))
WORKER_API_EMBEDDING_BATCH_SIZE = int(
    os.getenv("SPARKAI_WORKER_API_EMBEDDING_BATCH_SIZE", 4)
)
##### For the gradio web server
SERVER_ERROR_MSG = (
    "**网络错误或者负载过高，请等待或检查.**"
)

LOGDIR = os.getenv("LOGDIR", ".")

MODERATION_MSG = "$MODERATION$ YOUR INPUT VIOLATES OUR CONTENT MODERATION GUIDELINES."
CONVERSATION_LIMIT_MSG = "YOU HAVE REACHED THE CONVERSATION LENGTH LIMIT. PLEASE CLEAR HISTORY AND START A NEW CONVERSATION."
INACTIVE_MSG = "THIS SESSION HAS BEEN INACTIVE FOR TOO LONG. PLEASE REFRESH THIS PAGE."
SLOW_MODEL_MSG = "⚠️  Both models will show the responses all at once. Please stay patient as it may take over 30 seconds."
RATE_LIMIT_MSG = "**RATE LIMIT OF THIS MODEL IS REACHED. PLEASE COME BACK LATER OR TRY OTHER MODELS.**"
# Maximum input length
INPUT_CHAR_LEN_LIMIT = int(os.getenv("FASTCHAT_INPUT_CHAR_LEN_LIMIT", 12000))
# Maximum conversation turns
CONVERSATION_TURN_LIMIT = 50
# Session expiration time
SESSION_EXPIRATION_TIME = 3600


class ErrorCode(IntEnum):
    """
    https://platform.openai.com/docs/guides/error-codes/api-errors
    """

    VALIDATION_TYPE_ERROR = 40001

    INVALID_AUTH_KEY = 40101
    INCORRECT_AUTH_KEY = 40102
    NO_PERMISSION = 40103

    INVALID_MODEL = 40301
    PARAM_OUT_OF_RANGE = 40302
    CONTEXT_OVERFLOW = 40303

    RATE_LIMIT = 42901
    QUOTA_EXCEEDED = 42902
    ENGINE_OVERLOADED = 42903

    INTERNAL_ERROR = 50001
    CUDA_OUT_OF_MEMORY = 50002
    GRADIO_REQUEST_ERROR = 50003
    GRADIO_STREAM_UNKNOWN_ERROR = 50004
    CONTROLLER_NO_WORKER = 50005
    CONTROLLER_WORKER_TIMEOUT = 50006
