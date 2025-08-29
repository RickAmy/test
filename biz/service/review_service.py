#import sqlite3
# 替换原来的 import sqlite3
import pysqlite3 as sqlite3
import pandas as pd

from dataclasses import dataclass
from typing import List, Dict, Optional

from biz.entity.review_entity import MergeRequestReviewEntity, PushReviewEntity, GerritReviewEntity

from biz.entity.review_entity import MergeRequestReviewEntity, PushReviewEntity
# 在 review_service.py 顶部添加导入
from biz.gitlab.webhook_handler import filter_changes
from biz.gerrit.client import GerritClient
import os
import logging
logger = logging.getLogger(__name__)


#######
# 添加GerritReviewEntity类
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
        return "; ".join(commit.get("message", "").strip() for commit in self.commits)


class ReviewService:
    DB_FILE = "data/data.db"

    @staticmethod
    def init_db():
        """初始化数据库及表结构"""
        try:
            with sqlite3.connect(ReviewService.DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                        CREATE TABLE IF NOT EXISTS mr_review_log (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            project_name TEXT,
                            author TEXT,
                            source_branch TEXT,
                            target_branch TEXT,
                            updated_at INTEGER,
                            commit_messages TEXT,
                            score INTEGER,
                            url TEXT,
                            review_result TEXT,
                            additions INTEGER DEFAULT 0,
                            deletions INTEGER DEFAULT 0,
                            last_commit_id TEXT DEFAULT ''
                        )
                    ''')
                cursor.execute('''
                        CREATE TABLE IF NOT EXISTS push_review_log (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            project_name TEXT,
                            author TEXT,
                            branch TEXT,
                            updated_at INTEGER,
                            commit_messages TEXT,
                            score INTEGER,
                            review_result TEXT,
                            additions INTEGER DEFAULT 0,
                            deletions INTEGER DEFAULT 0
                        )
                    ''')
                
                cursor.execute('''
                        CREATE TABLE IF NOT EXISTS gerrit_patchset_review_log (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            project_name TEXT,
                            author TEXT,
                            branch TEXT,
                            updated_at INTEGER,
                            commit_messages TEXT,
                            score REAL,
                            review_result TEXT,
                            additions INTEGER DEFAULT 0,
                            deletions INTEGER DEFAULT 0,
                            patchset_number INTEGER,
                            change_id TEXT,
                            change_url TEXT
                        )
                    ''')

                # 确保旧版本的mr_review_log、push_review_log表添加additions、deletions列
                tables = ["mr_review_log", "push_review_log"]
                columns = ["additions", "deletions"]
                for table in tables:
                    cursor.execute(f"PRAGMA table_info({table})")
                    current_columns = [col[1] for col in cursor.fetchall()]
                    for column in columns:
                        if column not in current_columns:
                            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} INTEGER DEFAULT 0")

                # 为旧版本的mr_review_log表添加last_commit_id字段
                mr_columns = [
                    {
                        "name": "last_commit_id",
                        "type": "TEXT",
                        "default": "''"
                    }
                ]
                cursor.execute(f"PRAGMA table_info('mr_review_log')")
                current_columns = [col[1] for col in cursor.fetchall()]
                for column in mr_columns:
                    if column.get("name") not in current_columns:
                        cursor.execute(f"ALTER TABLE mr_review_log ADD COLUMN {column.get('name')} {column.get('type')} "
                                       f"DEFAULT {column.get('default')}")
                # 为gerrit_patchset_review_log表添加时间字段索引#######
                conn.execute('CREATE INDEX IF NOT EXISTS idx_gerrit_patchset_review_log_updated_at ON '
                           'gerrit_patchset_review_log (updated_at);')
                conn.commit()
                # 添加时间字段索引（默认查询就需要时间范围）
                conn.execute('CREATE INDEX IF NOT EXISTS idx_push_review_log_updated_at ON '
                             'push_review_log (updated_at);')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_mr_review_log_updated_at ON mr_review_log (updated_at);')
                ############这里是测试输出
                ReviewService.test_db_write()
        except sqlite3.DatabaseError as e:
            print(f"Database initialization failed: {e}")

    @staticmethod
    def insert_mr_review_log(entity: MergeRequestReviewEntity):
        """插入合并请求审核日志"""
        try:
            with sqlite3.connect(ReviewService.DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                                INSERT INTO mr_review_log (project_name,author, source_branch, target_branch, 
                                updated_at, commit_messages, score, url,review_result, additions, deletions, 
                                last_commit_id)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''',
                               (entity.project_name, entity.author, entity.source_branch,
                                entity.target_branch, entity.updated_at, entity.commit_messages, entity.score,
                                entity.url, entity.review_result, entity.additions, entity.deletions,
                                entity.last_commit_id))
                conn.commit()
        except sqlite3.DatabaseError as e:
            print(f"Error inserting review log: {e}")

    @staticmethod
    # def get_mr_review_logs(authors: list = None, project_names: list = None, updated_at_gte: int = None,
    #                        updated_at_lte: int = None) -> pd.DataFrame:
    #     """获取符合条件的合并请求审核日志"""
    #     try:
    #         with sqlite3.connect(ReviewService.DB_FILE) as conn:

    #             # query = """
    #             #             SELECT project_name, author, source_branch, target_branch, updated_at, commit_messages, score, url, review_result, additions, deletions
    #             #             FROM mr_review_log
    #             #             WHERE 1=1
    #             #             """
    #             query = """
    #                         SELECT project_name, author, source_branch, target_branch, updated_at, 
    #                             commit_messages, score, url, review_result, additions, deletions
    #                         FROM mr_review_log
    #                         UNION ALL
    #                         SELECT project_name, author, branch as source_branch, '' as target_branch, 
    #                             updated_at, commit_messages, score, change_url as url, 
    #                             review_result, additions, deletions
    #                         FROM gerrit_patchset_review_log
    #                         WHERE 1=1
    #                         """
    #             params = []

    #             if authors:
    #                 placeholders = ','.join(['?'] * len(authors))
    #                 query += f" AND author IN ({placeholders})"
    #                 params.extend(authors)

    #             if project_names:
    #                 placeholders = ','.join(['?'] * len(project_names))
    #                 query += f" AND project_name IN ({placeholders})"
    #                 params.extend(project_names)

    #             if updated_at_gte is not None:
    #                 query += " AND updated_at >= ?"
    #                 params.append(updated_at_gte)

    #             if updated_at_lte is not None:
    #                 query += " AND updated_at <= ?"
    #                 params.append(updated_at_lte)
    #             query += " ORDER BY updated_at DESC"
    #             df = pd.read_sql_query(sql=query, con=conn, params=params)
    #         return df
    #     except sqlite3.DatabaseError as e:
    #         print(f"Error retrieving review logs: {e}")
    #         return pd.DataFrame()
    @staticmethod
    def get_mr_review_logs(authors: list = None, project_names: list = None, updated_at_gte: int = None,
                        updated_at_lte: int = None) -> pd.DataFrame:
        """获取符合条件的合并请求审核日志"""
        try:
            with sqlite3.connect(ReviewService.DB_FILE) as conn:
                # 仅查询 mr_review_log 表
                query = """
                    SELECT project_name, author, source_branch, target_branch, updated_at, 
                        commit_messages, score, url, review_result, additions, deletions
                    FROM mr_review_log
                    WHERE 1=1
                """
                params = []

                if authors:
                    placeholders = ','.join(['?'] * len(authors))
                    query += f" AND author IN ({placeholders})"
                    params.extend(authors)

                if project_names:
                    placeholders = ','.join(['?'] * len(project_names))
                    query += f" AND project_name IN ({placeholders})"
                    params.extend(project_names)

                if updated_at_gte is not None:
                    query += " AND updated_at >= ?"
                    params.append(updated_at_gte)

                if updated_at_lte is not None:
                    query += " AND updated_at <= ?"
                    params.append(updated_at_lte)
                
                query += " ORDER BY updated_at DESC"
                
                df = pd.read_sql_query(sql=query, con=conn, params=params)
            return df
        except sqlite3.DatabaseError as e:
            print(f"Error retrieving review logs: {e}")
            return pd.DataFrame()

    @staticmethod
    def check_mr_last_commit_id_exists(project_name: str, source_branch: str, target_branch: str, last_commit_id: str) -> bool:
        """检查指定项目的Merge Request是否已经存在相同的last_commit_id"""
        try:
            with sqlite3.connect(ReviewService.DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT COUNT(*) FROM mr_review_log 
                    WHERE project_name = ? AND source_branch = ? AND target_branch = ? AND last_commit_id = ?
                ''', (project_name, source_branch, target_branch, last_commit_id))
                count = cursor.fetchone()[0]
                return count > 0
        except sqlite3.DatabaseError as e:
            print(f"Error checking last_commit_id: {e}")
            return False

    @staticmethod
    def insert_push_review_log(entity: PushReviewEntity):
        """插入推送审核日志"""
        try:
            with sqlite3.connect(ReviewService.DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                                INSERT INTO push_review_log (project_name,author, branch, updated_at, commit_messages, score,review_result, additions, deletions)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''',
                               (entity.project_name, entity.author, entity.branch,
                                entity.updated_at, entity.commit_messages, entity.score,
                                entity.review_result, entity.additions, entity.deletions))
                conn.commit()
        except sqlite3.DatabaseError as e:
            print(f"Error inserting review log: {e}")

    @staticmethod
    def insert_gerrit_patchset_review_log(entity: GerritReviewEntity):
        """插入Gerrit patchset审核日志"""
        try:
            with sqlite3.connect(ReviewService.DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO gerrit_patchset_review_log (
                        project_name, author, branch, updated_at, commit_messages, 
                        score, review_result, additions, deletions, 
                        patchset_number, change_id, change_url
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entity.project_name, 
                    entity.author, 
                    entity.branch,
                    entity.updated_at, 
                    entity.commit_messages,  # 使用属性而不是直接访问
                    entity.score,
                    entity.review_result, 
                    entity.additions, 
                    entity.deletions,
                    entity.patchset_number, 
                    entity.change_id, 
                    entity.change_url
                ))
                conn.commit()
        except sqlite3.DatabaseError as e:
            print(f"Error inserting gerrit patchset review log: {e}")

    

    @staticmethod
    def get_push_review_logs(authors: list = None, project_names: list = None, updated_at_gte: int = None,
                             updated_at_lte: int = None) -> pd.DataFrame:
        """获取符合条件的推送审核日志"""
        try:
            with sqlite3.connect(ReviewService.DB_FILE) as conn:
                # 基础查询
                query = """
                    SELECT project_name, author, branch, updated_at, commit_messages, score, review_result, additions, deletions
                    FROM push_review_log
                    WHERE 1=1
                """
                params = []

                # 动态添加 authors 条件
                if authors:
                    placeholders = ','.join(['?'] * len(authors))
                    query += f" AND author IN ({placeholders})"
                    params.extend(authors)

                if project_names:
                    placeholders = ','.join(['?'] * len(project_names))
                    query += f" AND project_name IN ({placeholders})"
                    params.extend(project_names)

                # 动态添加 updated_at_gte 条件
                if updated_at_gte is not None:
                    query += " AND updated_at >= ?"
                    params.append(updated_at_gte)

                # 动态添加 updated_at_lte 条件
                if updated_at_lte is not None:
                    query += " AND updated_at <= ?"
                    params.append(updated_at_lte)

                # 按 updated_at 降序排序
                query += " ORDER BY updated_at DESC"

                # 执行查询
                df = pd.read_sql_query(sql=query, con=conn, params=params)
                return df
        except sqlite3.DatabaseError as e:
            print(f"Error retrieving push review logs: {e}")
            return pd.DataFrame()
    def review_gerrit_change(self, project_name: str, branch: str, commit_id: str, change_url: str, commit_message: str):
        """
        对 Gerrit 变更执行代码审查并返回结果
        """
        # 从环境变量获取URL和Token
        base_url = os.getenv('GERRIT_BASE_URL')  # 确保.env中配置了GERRIT_BASE_URL
        token = os.getenv('GERRIT_PASSWORD')     # 或GERRIT_ACCESS_TOKEN
        username = os.getenv('GERRIT_USERNAME')

        # 初始化Gerrit客户端
        gerrit_client = GerritClient(
            base_url=base_url,  # 直接传入，无需拼接/a/
            token=token,
            username=username
        )
        
        # 1. 获取变更的代码差异
        changes = gerrit_client.get_changes(commit_id)
        
        # 2. 过滤支持的文件类型
        try:
            filtered_changes = filter_changes(changes)
        except NameError:
            # 如果 filter_changes 不可用，直接使用原始 changes
            filtered_changes = changes
        
        # 3. 调用 AI 审查
        if not filtered_changes:
            return "No supported files changed"
        
        return CodeReviewer().review_and_strip_code(str(filtered_changes), commit_message)
    
    @staticmethod
    def get_gerrit_review_logs(authors: list = None, project_names: list = None, 
                            updated_at_gte: int = None, updated_at_lte: int = None) -> pd.DataFrame:
        """获取Gerrit patchset审核日志"""
        try:
            with sqlite3.connect(ReviewService.DB_FILE) as conn:
                query = """
                    SELECT project_name, author, branch as source_branch, '' as target_branch, 
                        updated_at, commit_messages, score, change_url as url, 
                        review_result, additions, deletions
                    FROM gerrit_patchset_review_log
                    WHERE 1=1
                """
                params = []

                if authors:
                    placeholders = ','.join(['?'] * len(authors))
                    query += f" AND author IN ({placeholders})"
                    params.extend(authors)

                if project_names:
                    placeholders = ','.join(['?'] * len(project_names))
                    query += f" AND project_name IN ({placeholders})"
                    params.extend(project_names)

                if updated_at_gte is not None:
                    query += " AND updated_at >= ?"
                    params.append(updated_at_gte)

                if updated_at_lte is not None:
                    query += " AND updated_at <= ?"
                    params.append(updated_at_lte)

                query += " ORDER BY updated_at DESC"
                df = pd.read_sql_query(sql=query, con=conn, params=params)
            return df
        except sqlite3.DatabaseError as e:
            print(f"Error retrieving gerrit review logs: {e}")
            return pd.DataFrame()
        
    def test_db_write():
        try:
            with sqlite3.connect(ReviewService.DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO gerrit_patchset_review_log (project_name) VALUES ('test_write')")
                conn.commit()
                logger.info("测试写入成功")
        except Exception as e:
            logger.error(f"数据库写入测试失败: {e}")
    
    #######
    @staticmethod
    # def update_gerrit_patchset_review_log(entity: GerritReviewEntity):
    #     """更新Gerrit patchset审核日志"""
    #     try:
    #         with sqlite3.connect(ReviewService.DB_FILE) as conn:
    #             cursor = conn.cursor()
    #             cursor.execute('''
    #                 UPDATE gerrit_patchset_review_log 
    #                 SET review_result = ?, 
    #                     score = ?,
    #                     updated_at = ?,
    #                     additions = ?,
    #                     deletions = ?
    #                 WHERE change_id = ? AND patchset_number = ?
    #             ''', (
    #                 entity.review_result,
    #                 entity.score,
    #                 entity.updated_at,
    #                 entity.additions,
    #                 entity.deletions,
    #                 entity.change_id,
    #                 entity.patchset_number
    #             ))
    #             conn.commit()
    #     except sqlite3.DatabaseError as e:
    #         logger.error(f"更新Gerrit审查日志失败: {e}")
    @staticmethod
    def update_gerrit_patchset_review_log(entity: GerritReviewEntity):
        """更新Gerrit审查日志"""
        try:
            with sqlite3.connect(ReviewService.DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE gerrit_patchset_review_log 
                    SET review_result = ?,
                        score = ?,
                        updated_at = ?,
                        additions = ?,
                        deletions = ?
                    WHERE change_id = ? AND patchset_number = ?
                ''', (
                    entity.review_result,
                    entity.score,
                    entity.updated_at,
                    entity.additions,
                    entity.deletions,
                    entity.change_id,
                    entity.patchset_number
                ))
                if cursor.rowcount == 0:
                    logger.warning(f"No record updated for {entity.change_id}/{entity.patchset_number}")
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database update failed: {e}")


# Initialize database
ReviewService.init_db()