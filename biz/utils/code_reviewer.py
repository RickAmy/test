import abc
import json
import os
import re
from typing import Dict, Any, List

import yaml
from jinja2 import Template

from biz.llm.factory import Factory
from biz.utils.log import logger
from biz.utils.token_util import count_tokens, truncate_text_by_tokens


class BaseReviewer(abc.ABC):
    """代码审查基类"""

    def __init__(self, prompt_key: str):
        self.client = Factory().getClient()
        self.prompts = self._load_prompts(prompt_key, os.getenv("REVIEW_STYLE", "professional"))

    def _load_prompts(self, prompt_key: str, style="professional") -> Dict[str, Any]:
        """加载提示词配置"""
        prompt_templates_file = "conf/prompt_templates.yml"
        try:
            # 在打开 YAML 文件时显式指定编码为 UTF-8，避免使用系统默认的 GBK 编码。
            with open(prompt_templates_file, "r", encoding="utf-8") as file:
                prompts = yaml.safe_load(file).get(prompt_key, {})

                # 使用Jinja2渲染模板
                def render_template(template_str: str) -> str:
                    return Template(template_str).render(style=style)

                system_prompt = render_template(prompts["system_prompt"])
                user_prompt = render_template(prompts["user_prompt"])

                return {
                    "system_message": {"role": "system", "content": system_prompt},
                    "user_message": {"role": "user", "content": user_prompt},
                }
        except (FileNotFoundError, KeyError, yaml.YAMLError) as e:
            logger.error(f"加载提示词配置失败: {e}")
            raise Exception(f"提示词配置加载失败: {e}")

    def call_llm(self, messages: List[Dict[str, Any]]) -> str:
        """调用 LLM 进行代码审核"""
        #logger.info(f"向 AI 发送代码 Review 请求, messages: {messages}")
        review_result = self.client.completions(messages=messages)
        #logger.info(f"收到 AI 返回结果: {review_result}")
        return review_result

    @abc.abstractmethod
    def review_code(self, *args, **kwargs) -> str:
        """抽象方法，子类必须实现"""
        pass


class CodeReviewer(BaseReviewer):
    """代码 Diff 级别的审查"""

    def __init__(self):
        super().__init__("code_review_prompt")

    def review_and_strip_code(self, changes_text: str, commits_text: str = "") -> str:
        """
        Review判断changes_text超出取前REVIEW_MAX_TOKENS个token，超出则截断changes_text，
        调用review_code方法，返回review_result，如果review_result是markdown格式，则去掉头尾的```
        :param changes_text:
        :param commits_text:
        :return:
        """
        # 如果超长，取前REVIEW_MAX_TOKENS个token
        review_max_tokens = int(os.getenv("REVIEW_MAX_TOKENS", 10000))
        # 如果changes为空,打印日志
        if not changes_text:
            logger.info("代码为空, diffs_text = %", str(changes_text))
            return "代码为空"

        ###########################这里会截断过长的内容
        # 计算tokens数量，如果超过REVIEW_MAX_TOKENS，截断changes_text
        tokens_count = count_tokens(changes_text)
        logger.info(f"【当前changes_text的token数】: {tokens_count}，最大限制: {review_max_tokens}")  # 新增
        if tokens_count > review_max_tokens:
            old_changes = changes_text
            changes_text = truncate_text_by_tokens(changes_text, review_max_tokens)
            logger.info(f"【因超长截断changes_text】截断前包含hello.rs? {'hello.rs' in old_changes}，截断后包含? {'hello.rs' in changes_text}")  # 新增
        #####################
        #logger.info(f"传入LLM的完整变更内容: {changes_text}")  # 新增日志
        ####################

        review_result = self.review_code(changes_text, commits_text).strip()
        return self.parse_structured_review_result(review_result)
    
    def parse_structured_review_result(self, review_text: str) -> Dict:
        """
        解析AI返回的结构化评审结果，处理各种格式问题
        """
        # 清理可能的格式问题
        cleaned_text = review_text.strip()
        
        # 移除可能的额外引号和json标记
        if cleaned_text.startswith('"json'):
            cleaned_text = cleaned_text.replace('"json', '').strip()
        if cleaned_text.startswith('json'):
            cleaned_text = cleaned_text.replace('json', '').strip()
        if cleaned_text.startswith('`'):
            cleaned_text = cleaned_text.strip('`').strip()
        
        # 尝试提取JSON部分（多种模式）
        json_patterns = [
            r'```json\s*(\{.*?\})\s*```',
            r'```\s*(\{.*?\})\s*```',
            r'(\{.*\})'  # 直接匹配整个JSON
        ]
        
        for pattern in json_patterns:
            match = re.search(pattern, cleaned_text, re.DOTALL)
            if match:
                try:
                    json_str = match.group(1)
                    data = json.loads(json_str)
                    return self._validate_review_data(data)
                except (json.JSONDecodeError, AttributeError):
                    continue
        
        # 如果JSON解析失败，尝试其他格式
        try:
            return self._parse_markdown_review(cleaned_text)
        except Exception:
            return self._parse_natural_language_review(cleaned_text)
    
    def _validate_review_data(self, data):
        """验证和标准化评审数据"""
        return {
            "score": data.get("score", 0),
            "summary": data.get("summary", ""),
            "comments": data.get("comments", [])
        }
    
    def _parse_markdown_review(self, text):
        """解析Markdown格式的评审结果"""
        comments = []
        summary = ""
        score = 0
        
        # 提取总分
        score_match = re.search(r'总分[:：]\s*(\d+)', text)
        if score_match:
            score = int(score_match.group(1))
        
        # 提取行级评论（假设格式：文件名:行号 - 评论）
        comment_pattern = r'(\S+):(\d+)\s*[-:]\s*(.+)'
        for match in re.finditer(comment_pattern, text):
            file_path = match.group(1)
            line_num = int(match.group(2))
            message = match.group(3).strip()
            
            comments.append({
                "file": file_path,
                "line": line_num,
                "message": message
            })
        
        # 提取总结（第一段或最后一段）
        paragraphs = text.split('\n\n')
        if paragraphs:
            summary = paragraphs[0]
        
        return {
            "score": score,
            "summary": summary,
            "comments": comments
        }
    
    def _parse_natural_language_review(self, text):
        """解析自然语言格式的评审结果"""
        # 简单实现：只返回总结，没有行级评论
        score = self.parse_review_score(text)
        return {
            "score": score,
            "summary": text,
            "comments": []
        }

    def review_code(self, diffs_text: str, commits_text: str = "") -> str:
        """Review 代码并返回结果"""
        messages = [
            self.prompts["system_message"],
            {
                "role": "user",
                "content": self.prompts["user_message"]["content"].format(
                    diffs_text=diffs_text, commits_text=commits_text
                ),
            },
        ]
        return self.call_llm(messages)

    # @staticmethod
    # def parse_review_score(review_text: str) -> int:
    #     """
    #     根据审查文本返回评分(-2到+2)
    #     - +2: 代码优秀，可直接合并
    #     - +1: 有少量建议但可以合并
    #     - 0: 需要人工审查
    #     - -1: 需要修改后重新提交
    #     - -2: 有严重问题不能合并
    #     """
    #     positive_keywords = ['excellent', 'good', 'well done']
    #     negative_keywords = ['bug', 'error', 'fix', 'problem']
        
    #     positive_count = sum(review_text.lower().count(word) for word in positive_keywords)
    #     negative_count = sum(review_text.lower().count(word) for word in negative_keywords)
        
    #     if positive_count > negative_count + 2:
    #         return 2
    #     elif positive_count > negative_count:
    #         return 1
    #     elif negative_count > positive_count + 3:
    #         return -2
    #     elif negative_count > positive_count:
    #         return -1
    #     return 0
    @staticmethod
    def parse_review_score(review_text: str) -> int:
        """
        根据审查文本返回Gerrit兼容的评分(-2到+2)
        - +2: 代码优秀，可直接合并
        - +1: 有少量建议但可以合并
        - 0: 需要人工审查
        - -1: 需要修改后重新提交
        - -2: 有严重问题不能合并
        """
        if not review_text:
            return 0
        
        # 检查总分模式
        match = re.search(r"总分[:：]\s*(\d+)分?", review_text)
        if match:
            score = int(match.group(1))
            # 将100分制转换为-2到+2
            #if score >= 95: return 2
            if score >= 90: return 1
            if score >= 85: return 0
            #if score >= 80: return -1
            return -1
        
        # 基于关键词的评分
        positive_keywords = ['excellent', 'good', 'well done', '建议通过', '可以合并']
        negative_keywords = ['bug', 'error', 'fix', 'problem', '问题', '需要修改']
        
        positive_count = sum(review_text.lower().count(word) for word in positive_keywords)
        negative_count = sum(review_text.lower().count(word) for word in negative_keywords)
        
        if positive_count > negative_count + 90:
            return 1
        # elif positive_count > negative_count + 80:
        #     return 1
        # elif negative_count > positive_count - 60:
        #     return -2
        elif negative_count > positive_count - 70:
            return -1
        return 0

