from dataclasses import dataclass
from typing import List, Dict, Optional



#########原gitlab和github的合并与推送类
class MergeRequestReviewEntity:
    def __init__(self, project_name: str, author: str, source_branch: str, target_branch: str, updated_at: int,
                 commits: list, score: float, url: str, review_result: str, url_slug: str, webhook_data: dict,
                 additions: int, deletions: int, last_commit_id: str):
        self.project_name = project_name
        self.author = author
        self.source_branch = source_branch
        self.target_branch = target_branch
        self.updated_at = updated_at
        self.commits = commits
        self.score = score
        self.url = url
        self.review_result = review_result
        self.url_slug = url_slug
        self.webhook_data = webhook_data
        self.additions = additions
        self.deletions = deletions
        self.last_commit_id = last_commit_id

    @property
    def commit_messages(self):
        # 合并所有 commit 的 message 属性，用分号分隔
        return "; ".join(commit["message"].strip() for commit in self.commits)


class PushReviewEntity:
    def __init__(self, project_name: str, author: str, branch: str, updated_at: int, commits: list, score: float,
                 review_result: str, url_slug: str, webhook_data: dict, additions: int, deletions: int):
        self.project_name = project_name
        self.author = author
        self.branch = branch
        self.updated_at = updated_at
        self.commits = commits
        self.score = score
        self.review_result = review_result
        self.url_slug = url_slug
        self.webhook_data = webhook_data
        self.additions = additions
        self.deletions = deletions

        @property
        def commit_messages(self):
            # 合并所有 commit 的 message 属性，用分号分隔
            return "; ".join(commit["message"].strip() for commit in self.commits)


@dataclass
class GerritReviewEntity:
    """Gerrit patchset审查实体类"""
    project_name: str
    author: str
    branch: str
    updated_at: int
    commits: List[Dict]  # 提交列表
    score: float
    review_result: str
    additions: int
    deletions: int
    patchset_number: int  # Gerrit特有的patchset编号
    change_id: str  # Gerrit特有的change ID
    change_url: Optional[str] = None  # Gerrit变更的URL
    url_slug: Optional[str] = None  # URL简写标识
    webhook_data: Optional[Dict] = None  # 原始webhook数据

    
    @property
    def commit_messages(self):
        """合并所有commit的message属性，用分号分隔"""
        if not self.commits:
            return "No commit messages"
        
        messages = []
        for commit in self.commits:
            # 处理commit可能是dict或字符串的情况
            if isinstance(commit, dict):
                message = commit.get("message", "No message").strip()
            else:
                message = str(commit).strip()
            messages.append(message)
        
        return "; ".join(msg for msg in messages if msg)

    

