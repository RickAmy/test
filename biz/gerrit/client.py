import requests
import base64
import json
import os
import paramiko
from biz.utils.log import logger
from typing import List, Dict
import tempfile
import re
import subprocess


class GerritClient:
    def __init__(
        self, base_url: str, token: str, username: str, use_ssh: bool = False
    ):
        if not base_url:
            raise ValueError("base_url不能为空")

        self.use_ssh = use_ssh
        self.base_url = base_url.rstrip('/')  # 始终设置base_url

        if use_ssh:
            # SSH模式配置
            self.ssh_host = base_url.split('@')[-1].split(':')[0]
            self.ssh_port = (
                int(base_url.split(':')[-1])
                if ':' in base_url
                else 29418
            )
            self.ssh_username = username
            self.ssh_key_path = os.getenv('GERRIT_SSH_KEY_PATH')
            # self.ssh_key_path = os.getenv(
            #     'GERRIT_SSH_KEY_PATH',
            #     '~/.ssh/id_rsa'
            # )
        else:
            # HTTP模式配置
            self.token = token
            self.username = username
            self.auth = (username, token) if username else None

    def _make_ssh_request(self, command: str) -> str:
        """通过SSH执行Gerrit命令"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logger.debug(
            "SSH连接参数：host=%s, port=%s, user=%s, key=%s",
            self.ssh_host, self.ssh_port, self.ssh_username, self.ssh_key_path
        )
        try:
            ssh.connect(
                hostname=self.ssh_host,
                port=self.ssh_port,
                username=self.ssh_username,
                key_filename=os.path.expanduser(self.ssh_key_path),
                timeout=10
            )
            logger.debug(f"执行ssh命令：{command}")
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            logger.debug(f"ssh命令原始输出：\n{output}")

            if error:
                logger.error(f"SSH command error: {error}")
                raise Exception(f"SSH command failed: {error}")

            return output
        except Exception as e:
            logger.error(f"SSH连接失败: {str(e)}")
            raise
        finally:
            ssh.close()

    def _make_request(self, method, url, **kwargs):
        """统一的请求方法（支持SSH和HTTP）"""
        if self.use_ssh:
            # SSH模式处理特定API请求
            if '/a/changes/' in url:
                change_id = url.split('/')[-1].split('?')[0]
                gerrit_command = f"gerrit query --format=JSON {change_id}"
                return self._make_ssh_request(gerrit_command)
            elif '/review' in url:
                # 处理review提交
                change_id = url.split('/')[4]
                revision = url.split('/')[6]
                message = kwargs.get('json', {}).get('message', '')
                json_data = kwargs.get('json', {})
                labels = json_data.get('labels', {})
                score = labels.get('Code-Review', 0)
                command = (
                    f"gerrit review --code-review {score} "
                    f"--message '{message}' {revision}"
                )
                return self._make_ssh_request(command)
            else:
                raise NotImplementedError(f"SSH模式不支持该API: {url}")
        else:
            # HTTP模式保持原有逻辑
            auth_str = f"{self.username}:{self.token}".encode()
            base64_auth = base64.b64encode(auth_str).decode()
            headers = {
                "Authorization": f"Basic {base64_auth}",
                "Accept": "application/json",
            }
            try:
                response = requests.request(
                    method, url,
                    headers=headers,
                    timeout=30,
                    **kwargs
                )
                response.raise_for_status()
                content = response.text
                if content.startswith(")]}'\n"):
                    return content[5:]
                return content
            except requests.exceptions.RequestException as e:
                logger.error(f"Gerrit API请求失败: {e}")
                raise

    def post_comment(self, change_id: str, revision: str, message: str):
        """提交评论到 Gerrit"""
        url = (
            f"{self.base_url}/a/changes/{change_id}/"
            f"revisions/{revision}/review"
        )

        try:
            # 使用Basic Auth认证
            auth = (self.username, self.token) if self.username else None
            payload = {
                "message": message,
                "comments": {}
            }
            response = requests.post(
                url,
                auth=auth,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            logger.info(f"Comment posted to Gerrit change {change_id}")
        except Exception as e:
            logger.error(f"Failed to post Gerrit comment: {e}")

    def post_review(
        self, change_id: str, revision: str, score: int, message: str,
        comments: List[Dict] = None
    ):
        """提交评分和行级评论到 Gerrit（支持SSH和HTTP模式）"""
        score = max(-2, min(2, score))

        if self.use_ssh:
            # SSH 模式：使用 gerrit review 命令
            return self._post_review_ssh(
                change_id, revision, score, message, comments
            )
        else:
            # HTTP 模式
            return self._post_review_http(
                change_id, revision, score, message, comments
            )

    # http模式提交评论
    def _post_review_http(self, change_id, revision, score, message, comments):
        """HTTP 模式提交评审"""
        payload = {
            "message": message,
            "labels": {
                "Code-Review": score,
                "Verified": 1 if score >= 0 else -1
            }
        }

        if comments:
            formatted_comments = {}
            for comment in comments:
                file_path = comment["file"]
                if file_path not in formatted_comments:
                    formatted_comments[file_path] = []
                formatted_comments[file_path].append({
                    "line": comment["line"],
                    "message": comment["message"]
                })
            payload["comments"] = formatted_comments

        url = (
            f"{self.base_url}/a/changes/{change_id}/"
            f"revisions/{revision}/review"
        )

        try:
            auth = (self.username, self.token) if self.username else None
            response = requests.post(
                url,
                auth=auth,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            comment_count = len(comments) if comments else 0
            logger.info(
                f"Review score {score} and {comment_count} comments "
                f"posted to Gerrit change {change_id}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to post Gerrit review: {e}")
            return False

    # ssh模式提交评论
    def _post_review_ssh(self, change_id, revision, score, message, comments):
        """SSH 模式提交评审（遵循Gerrit 3.9.11官方语法：--json 读标准输入）"""
        try:
            # 1. 构建Gerrit兼容的JSON（复用之前的转义逻辑，确保格式正确）
            review_json = self._build_gerrit_json(score, message, comments)
            # 打印前300字符，避免日志过长
            logger.debug(f"待传递的评审JSON: {review_json[:300]}...")

            # 2. 构造官方标准命令：--json 在前，提交ID在后（无多余"-"）
            # 关键：--json 选项单独使用，Gerrit自动从stdin读JSON，无需加"-"
            command = f"gerrit review --json {revision}"
            logger.debug(f"执行SSH命令: {command}")

            # 3. 建立SSH连接，通过标准输入传递JSON（核心：正确使用stdin）
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=self.ssh_host,
                port=self.ssh_port,
                username=self.ssh_username,
                key_filename=os.path.expanduser(self.ssh_key_path),
                timeout=15  # 延长超时时间，避免大JSON传递超时
            )

            # 4. 执行命令并发送JSON到stdin
            stdin, stdout, stderr = ssh.exec_command(command)
            stdin.write(review_json)  # 将JSON写入标准输入
            stdin.flush()  # 确保所有数据发送到Gerrit
            stdin.close()  # 关闭stdin，触发Gerrit解析JSON

            # 5. 获取执行结果（Gerrit成功时可能无输出，失败时 stderr 有信息）
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            ssh.close()

            # 6. 处理结果（无错误即视为成功，Gerrit 3.9.11 成功时通常无输出）
            if error:
                logger.error(f"Gerrit评审提交失败: {error}")
                raise Exception(f"Gerrit command error: {error}")
            gerrit_output = output if output else '无额外输出'
            logger.info(
                f"SSH评审提交成功（Gerrit返回）: {gerrit_output}"
            )
            return True

        except Exception as e:
            logger.error(f"SSH review failed: {str(e)}", exc_info=True)
            return False

    def _build_gerrit_json(self, score, message, comments):
        """构建Gerrit 3.9.11合规的JSON（转义特殊字符，紧凑格式）"""
        review_data = {
            # 转义双引号和换行
            "message": (
                message.replace('"', '\\"')
                .replace('\n', '\\n')
                .strip()
            ),
            # 固定为0，符合需求
            "labels": {"Code-Review": score},
            # 即使无评论也保留，避免Gerrit解析警告
            "comments": {}
        }

        # 处理行级评论（过滤无效评论）
        if comments and isinstance(comments, list):
            for comment in comments:
                required_keys = ["file", "line", "message"]
                if not all(key in comment for key in required_keys):
                    logger.warning(f"跳过无效行级评论: {comment}")
                    continue
                # 转义评论内容中的特殊字符
                file_path = comment["file"].strip()
                # 确保行号是整数
                line = int(comment["line"])
                msg = (
                    comment["message"]
                    .replace('"', '\\"')
                    .replace('\n', '\\n')
                    .strip()
                )
                # 添加到评论字典（Gerrit要求：key为文件路径，value为评论列表）
                if file_path not in review_data["comments"]:
                    review_data["comments"][file_path] = []
                review_data["comments"][file_path].append(
                    {"line": line, "message": msg, "unresolved": True}
                )

        # 生成紧凑JSON（无多余空格，Gerrit解析更快）
        return json.dumps(
            review_data,
            ensure_ascii=False,
            separators=(',', ':')
        )

    def _build_comment_file(self, revision, comments, summary_message):
        """构建Gerrit SSH模式评论文件格式"""
        content = []

        # Gerrit SSH评论文件格式要求：
        # 每行格式: file:line: message
        # 空行和#开头的行会被忽略

        # 添加行级评论
        if comments:
            for comment in comments:
                file_path = comment["file"]
                line = comment["line"]
                message = comment["message"]

                # 清理消息中的换行符（SSH模式不支持多行评论）
                message = message.replace('\n', '; ').replace('\r', '')

                # Gerrit SSH评论格式: file:line: message
                comment_line = f"{file_path}:{line}: {message}"
                content.append(comment_line)

        # 添加总结评论（作为普通评论）
        if summary_message:
            # 总结评论可以放在第一个文件的第一行
            if content:
                # 修改第一个评论，添加总结前缀
                first_comment = content[0]
                summary = summary_message[:100]
                content[0] = f"{first_comment} [总结: {summary}...]"
            else:
                # 如果没有行级评论，创建一个总结评论
                file_path = comments[0]['file'] if comments else 'default'
                content.append(
                    f"{list(file_path)}:1: [AI审查总结] "
                    f"{summary_message}"
                )

        return "\n".join(content)

    def get_changes(self, commit_id: str, diff_only: bool = False) -> List[Dict]:
        """
        获取指定commit的所有变更文件（含diff、新增/删除行数、文件状态）
        - SSH模式：通过gerrit query获取元数据，代码内过滤统计行，_fetch_diff拉取diff
        - HTTP模式：通过Gerrit REST API获取数据，兼容原有逻辑
        - 自动过滤不支持的文件类型（从环境变量SUPPORTED_EXTENSIONS读取）

        Args:
            commit_id: Gerrit提交ID（如6022b439ef2ef38dd062fbf770e3c9a7f429a606）

        Returns:
            List[Dict]: 格式化的变更列表，每个元素含filename/additions/deletions/diff/status
        """
        logger.info(f"开始获取变更内容，commit_id: {commit_id}")
        parsed_changes = []  # 最终返回的格式化变更列表
        # 支持的文件扩展名
        default_exts = ".c,.rs,.java,.py"
        supported_exts = os.getenv(
            "SUPPORTED_EXTENSIONS", default_exts
        ).split(",")
        # 清理空值（过滤空字符串扩展名）
        supported_exts = [ext.strip() for ext in supported_exts if ext.strip()]

        try:
            # --------------------------
            # 1. 解析变更元数据（change_id、revision_id、文件列表）
            # --------------------------
            if self.use_ssh:
                # SSH模式：执行纯gerrit query命令（无管道），代码内过滤统计行
                gerrit_cmd = (
                    "gerrit query --format=JSON --current-patch-set "
                    f"--files commit:{commit_id}"
                )
                logger.debug(f"SSH模式执行命令: {gerrit_cmd}")

                # 执行SSH命令获取原始输出
                raw_output = self._make_ssh_request(gerrit_cmd)
                if not raw_output:
                    logger.error("SSH模式未获取到变更元数据（原始输出为空）")
                    return parsed_changes

                # 过滤掉 "type":"stats" 的统计行，保留有效变更数据行
                valid_lines = []
                for line in raw_output.splitlines():
                    line = line.strip()
                    if line and '"type":"stats"' not in line:
                        valid_lines.append(line)

                if not valid_lines:
                    logger.error("SSH模式未获取到有效变更数据（已过滤统计行）")
                    return parsed_changes

                # 解析有效JSON数据（Gerrit query通常返回1行有效变更数据）
                change_metadata = json.loads(valid_lines[0])
                # 提取change_id（如I4fa11cdc...）
                change_id = change_metadata.get("id")
                current_patchset = change_metadata.get("currentPatchSet", {})
                # 提取revision_id（用于拉取diff）
                revision_id = current_patchset.get("revision", "")
                # 提取文件列表（过滤空文件路径）
                files = current_patchset.get("files", [])
                file_list = [f.get("file") for f in files if f.get("file")]

                # 校验关键元数据
                if not (change_id and revision_id and file_list):
                    logger.error(
                        "SSH模式元数据不完整：change_id=%s, revision_id=%s, "
                        "file_list=%s",
                        change_id, revision_id, file_list
                    )
                    return parsed_changes

            else:
                # HTTP模式：通过Gerrit REST API获取元数据（兼容原有逻辑）
                http_url = (
                    f"{self.base_url}/a/changes/?q=commit:{commit_id}"
                    "&o=ALL_REVISIONS&o=ALL_FILES"
                )
                logger.debug(f"HTTP模式请求URL: {http_url}")

                raw_response = self._make_http_request("GET", http_url)
                if not raw_response:
                    logger.error("HTTP模式未获取到变更元数据（响应为空）")
                    return parsed_changes

                # 解析HTTP响应（Gerrit API返回列表，第一个元素为目标变更）
                change_metadata_list = json.loads(raw_response)
                if (not isinstance(change_metadata_list, list)
                        or not change_metadata_list):
                    logger.error("HTTP模式变更元数据格式错误（非列表或空列表）")
                    return parsed_changes

                change_metadata = change_metadata_list[0]
                change_id = change_metadata.get("id")
                revision_id = change_metadata.get("current_revision", "")
                # 从revision中提取文件列表（HTTP模式文件列表存储在revisions下）
                revisions = change_metadata.get("revisions", {})
                revision_data = revisions.get(revision_id, {})
                files = revision_data.get("files", {})
                file_list = list(files.keys())

                # 校验关键元数据
                if not (change_id and revision_id and file_list):
                    logger.error(
                        "HTTP模式元数据不完整：change_id=%s, revision_id=%s, "
                        "file_list=%s",
                        change_id, revision_id, file_list
                    )
                    return parsed_changes

            # --------------------------
            # 2. 过滤支持的文件类型
            # --------------------------
            filtered_files = []
            for file_path in file_list:
                # 跳过空路径或目录（避免无效文件处理）
                if not file_path or file_path.endswith("/"):
                    continue
                # 检查文件扩展名是否在支持列表中
                if any(file_path.endswith(ext) for ext in supported_exts):
                    filtered_files.append(file_path)

            if not filtered_files:
                logger.info(
                    "无支持的文件类型变更（支持扩展名：%s，原始文件列表：%s）",
                    supported_exts, file_list
                )
                return parsed_changes
            logger.debug(f"过滤后待处理文件：{filtered_files}（共{len(filtered_files)}个）")

            # --------------------------
            # 3. 遍历文件获取diff和元数据（新增/删除行数、状态）
            # --------------------------
            for file_path in filtered_files:
                try:
                    # 3.2 获取文件元数据（新增行数、删除行数、状态：added/modified/deleted）
                    file_info = self._get_file_info(
                        change_id=change_id,
                        file_path=file_path
                    )
                    # Gerrit用insertions表示新增行数
                    additions = file_info.get("insertions", 0)
                    # Gerrit用deletions表示删除行数
                    deletions = file_info.get("deletions", 0)
                    # 文件状态
                    file_status = file_info.get("type", "modified").lower()
                    parents = current_patchset.get("parents", [])
                    parent_commit = parents[0] if parents else None
                    # 3.1 获取文件diff内容（调用已实现的_fetch_diff方法）
                    if self.use_ssh:
                        # SSH模式：_fetch_diff需change_id和file_path（revision_id从元数据提取，无需额外传入）
                        # 获取patchset_num（从current_patchset中提取）
                        patchset_num = current_patchset.get("number", 1)
                        if diff_only:
                            diff_content = self._fetch_diff_hunks(
                                change_id=change_id,
                                file_path=file_path,
                                patchset_num=patchset_num,
                                parent_commit=parent_commit
                            )
                            line_map = {}  # 暂不做精确行号映射，可后续增强
                        else:
                            diff_content, line_map = self._fetch_diff(
                                change_id=change_id,
                                file_path=file_path,
                                revision_id=revision_id,
                                patchset_num=patchset_num
                            )
                        logger.debug(
                            "文件%s的diff内容: %s...",
                            file_path, diff_content[:200]
                        )
                    else:
                        # HTTP模式：_fetch_diff需change_id、revision_id、file_path
                        diff_content = self._fetch_diff(
                            change_id=change_id,
                            revision_id=revision_id,
                            file_path=file_path
                        )

                    # 3.3 格式化变更数据（统一字段名，便于后续处理）
                    parsed_change = {
                        "filename": file_path,
                        "additions": additions,
                        "deletions": deletions,
                        "diff": (
                            diff_content.strip()
                            if diff_content
                            else "# 未获取到diff内容"
                        ),
                        "status": file_status,
                        # 新增行号映射
                        "line_map": line_map
                    }
                    parsed_changes.append(parsed_change)
                    logger.debug(
                        "成功处理文件：%s（新增%s行，删除%s行，状态：%s）",
                        file_path, additions, deletions, file_status
                    )

                except Exception as file_e:
                    logger.warning(
                        "处理文件%s失败：%s",
                        file_path, str(file_e),
                        exc_info=True
                    )
                    continue

            logger.info(
                "变更获取完成：共处理%s/%s个文件（commit_id：%s）",
                len(parsed_changes), len(filtered_files), commit_id
            )
            return parsed_changes

        except Exception as e:
            logger.error(f"get_changes整体执行失败：{str(e)}", exc_info=True)
            return parsed_changes

    # 获取代码差异
    def _fetch_diff(
        self,
        change_id: str,
        file_path: str,
        revision_id: str,
        patchset_num: int
    ) -> tuple[str, dict]:
        """仅拉取当前提交的指定文件内容，使用绝对行号"""
        try:
            project = self._get_project_name_from_change(change_id)
            if not project:
                return "# 无法获取项目名称", {}
            change_num = self._extract_change_number(change_id)
            ref = f"refs/changes/{change_num[-2:]}/{change_num}/{patchset_num}"

            with tempfile.TemporaryDirectory(
                prefix="gerrit_diff_"
            ) as temp_dir:
                # 1. 拉取指定ref的代码（仅当前提交，--depth 1）
                ssh_addr = (
                    f"ssh://{self.ssh_username}@{self.ssh_host}:"
                    f"{self.ssh_port}/{project}"
                )
                commands = [
                    f"cd {temp_dir}",
                    f"git init",
                    f"git remote add origin {ssh_addr}",
                    f"git fetch --depth 1 origin {ref}",  # 仅拉取当前提交
                    f"git checkout FETCH_HEAD -- {file_path}"  # 只检出需要的文件
                ]
                result = subprocess.run(
                    " && ".join(commands),
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode != 0:
                    logger.error(f"git命令执行失败: {result.stderr}")
                    return f"# 命令执行失败: {result.stderr}", {}

                # 2. 读取文件内容
                file_full_path = os.path.join(temp_dir, file_path)
                if not os.path.exists(file_full_path):
                    return "# 文件不存在于当前提交", {}

                with open(
                    file_full_path,
                    'r',
                    encoding='utf-8',
                    newline=''
                ) as f:
                    file_content = f.read()

                # 3. 构建行号映射（当前提交的行号就是绝对行号）
                line_count = file_content.count('\n') + 1  # 处理最后一行无换行的情况
                line_map = {i+1: i+1 for i in range(line_count)}

                return file_content, line_map
        except Exception as e:
            logger.error(f"获取文件内容时出错: {str(e)}")
            return f"# 获取文件内容失败: {str(e)}", {}

    #差异审查
    def _fetch_diff_hunks(
        self,
        change_id: str,
        file_path: str,
        patchset_num: int,
        parent_commit: str = None
    ) -> str:
        """
        获取基线版本与当前patchset之间的差异
        仅返回 diff hunk，不影响原有 _fetch_diff()
        """
        try:
            project = self._get_project_name_from_change(change_id)
            if not project:
                return "# 无法获取项目名称"

            change_num = self._extract_change_number(change_id)
            ref = f"refs/changes/{change_num[-2:]}/{change_num}/{patchset_num}"

            ssh_addr = f"ssh://{self.ssh_username}@{self.ssh_host}:{self.ssh_port}/{project}"

            with tempfile.TemporaryDirectory(prefix="gerrit_diff_") as temp_dir:
                old_dir = os.path.join(temp_dir, "old")
                new_dir = os.path.join(temp_dir, "new")
                os.makedirs(old_dir, exist_ok=True)
                os.makedirs(new_dir, exist_ok=True)

                # 拉取新版本文件
                commands_new = [
                    f"cd {new_dir}",
                    "git init",
                    f"git remote add origin {ssh_addr}",
                    f"git fetch --depth 1 origin {ref}",
                    f"git checkout FETCH_HEAD -- {file_path}"
                ]
                result = subprocess.run(" && ".join(commands_new), shell=True, capture_output=True, text=True, timeout=1200)
                if result.returncode != 0:
                    return f"# 获取新版本失败: {result.stderr}"

                new_file = os.path.join(new_dir, file_path)
                if not os.path.exists(new_file):
                    return "# 新版本文件不存在"

                # 拉取基线版本文件
                old_file = None
                if parent_commit:
                    commands_old = [
                        f"cd {old_dir}",
                        "git init",
                        f"git remote add origin {ssh_addr}",
                        f"git fetch --depth 1 origin {parent_commit}",
                        f"git checkout FETCH_HEAD -- {file_path}"
                    ]
                    result = subprocess.run(" && ".join(commands_old), shell=True, capture_output=True, text=True, timeout=1200)
                    if result.returncode == 0:
                        old_file = os.path.join(old_dir, file_path)

                # 读取内容
                with open(new_file, "r", encoding="utf-8", errors="ignore") as f:
                    new_lines = f.readlines()
                if old_file and os.path.exists(old_file):
                    with open(old_file, "r", encoding="utf-8", errors="ignore") as f:
                        old_lines = f.readlines()
                else:
                    old_lines = []

                # 生成 diff hunk
                import difflib
                diff = difflib.unified_diff(
                    old_lines,
                    new_lines,
                    fromfile=f"a/{file_path}",
                    tofile=f"b/{file_path}",
                    lineterm=""
                )
                return "\n".join(diff) if diff else "# 无差异"
        except Exception as e:
            return f"# 获取diff失败: {str(e)}"

    def _extract_change_number(self, change_id: str) -> str:
        """从change_id中提取变更编号（数字部分）"""
        # 从change_id的元数据中获取number字段（更可靠的方式）
        change_metadata = self._get_change_metadata_by_id(change_id)
        return str(change_metadata.get("number", ""))

    def _get_patchset_info(self, change_id: str) -> dict:
        """辅助方法：从change_id获取当前patchset元数据（编号、revision等）"""
        if self.use_ssh:
            cmd = f"gerrit query --format=JSON --current-patch-set {change_id}"
            result = self._make_ssh_request(cmd)
            # 只解析第一行有效数据（过滤统计行）
            for line in result.splitlines():
                if line.startswith('{') and '"type":"stats"' not in line:
                    return json.loads(line).get("currentPatchSet", {})
            return {}  # 未找到有效数据
        else:
            # 保持原有HTTP模式逻辑
            url = f"{self.base_url}/a/changes/{change_id}?o=CURRENT_REVISION"
            result = self._make_http_request("GET", url)
            if not result:
                return {}
            return json.loads(result).get("currentPatchSet", {})

    def _get_project_name_from_change(self, change_id: str) -> str:
        """辅助方法：从change_id获取Gerrit项目名（修复多JSON行解析问题）"""
        if self.use_ssh:
            cmd = f"gerrit query --format=JSON {change_id}"
            result = self._make_ssh_request(cmd)
            if not result:
                return ""
            # 过滤统计行，仅保留第一行有效JSON
            for line in result.splitlines():
                line = line.strip()
                if line and '"type":"stats"' not in line:
                    try:
                        return json.loads(line).get("project", "")
                    except json.JSONDecodeError as e:
                        logger.error(f"解析项目名失败: {str(e)}, 行内容: {line}")
                        return ""
            return ""  # 无有效数据
        else:
            url = f"{self.base_url}/a/changes/{change_id}"
            result = self._make_http_request("GET", url)
            return json.loads(result).get("project", "") if result else ""

    def _get_patchset_ref(self, change_id: str, patchset_number: int) -> str:
        """辅助方法：生成Gerrit patchset的Git引用（如refs/changes/05/2305/2）"""
        # 方案1：从change_id提取十六进制部分（兼容I+UUID格式）
        # 匹配I后的40位十六进制字符（0-9, a-f, A-F）
        change_id_match = re.search(r"I([0-9a-fA-F]{40})", change_id)
        if not change_id_match:
            raise ValueError(f"change_id格式错误（需为I+40位十六进制字符）：{change_id}")

        # 方案2：从元数据获取正确的变更编号（number字段，如2305）
        # 优先使用元数据中的number，避免从change_id解析的风险
        change_metadata = self._get_change_metadata_by_id(change_id)
        change_num = change_metadata.get("number")
        if not change_num:
            raise ValueError(f"无法从change_id获取变更编号：{change_id}")

        # Gerrit标准ref格式：refs/changes/<后两位>/<完整数字>/<patchset号>
        change_num_str = str(change_num)
        last_two_digits = (
            change_num_str[-2:]
            if len(change_num_str) >= 2
            else f"0{change_num_str[-1]}"
        )
        return (
            f"refs/changes/{last_two_digits}/"
            f"{change_num_str}/{patchset_number}"
        )

    def _get_change_metadata_by_id(self, change_id: str) -> dict:
        """通过change_id获取元数据（主要用于提取number字段）"""
        if self.use_ssh:
            cmd = f"gerrit query --format=JSON {change_id}"
            result = self._make_ssh_request(cmd)
            for line in result.splitlines():
                if line.startswith('{') and '"type":"stats"' not in line:
                    return json.loads(line)
            return {}
        else:
            url = f"{self.base_url}/a/changes/{change_id}"
            result = self._make_http_request("GET", url)
            return json.loads(result) if result else {}

    def _get_file_status(self, change_id: str, file_path: str) -> str:
        """辅助方法：获取文件状态（added/deleted/modified）"""
        if self.use_ssh:
            cmd = (
                f"gerrit query --format=JSON --current-patch-set "
                f"--files {change_id}"
            )
            result = self._make_ssh_request(cmd)
            if not result:
                return "unknown"
            change_data = json.loads(result)
            current_patchset = change_data.get("currentPatchSet", {})
            for file_info in current_patchset.get("files", []):
                if file_info.get("file") == file_path:
                    return file_info.get("type", "modified").lower()
            return "unknown"
        else:
            url = f"{self.base_url}/a/changes/{change_id}?o=ALL_FILES"
            result = self._make_http_request("GET", url)
            change_data = json.loads(result)
            revision_id = change_data.get("current_revision")
            file_info = change_data.get("revisions", {})
            file_info = file_info.get(revision_id, {})
            file_info = file_info.get("files", {})
            file_info = file_info.get(file_path, {})
            return file_info.get("type", "modified").lower()

    def _encode_file_path(self, file_path: str) -> str:
        """辅助方法：编码文件路径（处理Gerrit API的特殊字符）"""
        import urllib.parse
        # 保留/，对其他特殊字符编码（如空格、中文、#）
        return urllib.parse.quote(file_path, safe='/')

    def _get_diff_from_gerrit_query(
        self, change_id: str, file_path: str
    ) -> str:
        """从 gerrit query 结果中提取差异（备选方案，通常仅在 git show 失败时使用）"""
        command = (
            f"gerrit query --format=JSON --current-patch-set "
            f"--files {change_id}"
        )
        result = self._make_ssh_request(command)
        try:
            for line in result.splitlines():
                if line.startswith('{') and '"type":"stats"' not in line:
                    data = json.loads(line)
                    current_patchset = data.get('currentPatchSet', {})
                    for file_info in current_patchset.get('files', []):
                        if (file_info.get('file') == file_path
                                and 'diff' in file_info):
                            return file_info['diff']
            return "无法获取差异内容（gerrit query 未包含详细 diff）"
        except Exception as e:
            logger.error(f"从 gerrit query 提取差异失败: {str(e)}")
            return ""

    def _get_file_info(self, change_id: str, file_path: str) -> dict:
        """获取文件元信息（修复多行JSON解析问题）"""
        command = (
            f"gerrit query --format=JSON --current-patch-set "
            f"--files {change_id} {file_path}"
        )
        result = self._make_ssh_request(command)
        try:
            # 过滤掉统计行，只保留有效变更数据行
            for line in result.splitlines():
                line = line.strip()
                if line and '"type":"stats"' not in line:
                    data = json.loads(line)
                    if ('currentPatchSet' in data
                            and 'files' in data['currentPatchSet']):
                        for file_info in data['currentPatchSet']['files']:
                            if file_info.get('file') == file_path:
                                return file_info
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败（内容：{result}）: {str(e)}")
            return {}
        except Exception as e:
            logger.error(f"获取文件信息失败: {str(e)}")
            return {}

    def _get_file_list(self, change_id: str) -> list:
        """SSH模式下获取变更文件列表"""
        if not self.use_ssh:
            return []

        command = (
            f"gerrit query --format=JSON --current-patch-set "
            f"--files {change_id}"
        )
        result = self._make_ssh_request(command)
        try:
            files = []
            for line in result.splitlines():
                if line.startswith('{') and '"type":"stats"' not in line:
                    data = json.loads(line)
                    if ('currentPatchSet' in data
                            and 'files' in data['currentPatchSet']):
                        # 正确解析文件列表
                        for file_info in data['currentPatchSet']['files']:
                            if 'file' in file_info:
                                files.append(file_info['file'])
            return files
        except Exception as e:
            logger.error(f"获取文件列表失败: {e}")
            return []

    def _get_change_metadata(self, commit_id: str):
        """获取变更基础信息"""
        if self.use_ssh:
            gerrit_command = f"gerrit query --format=JSON commit:{commit_id}"
            result = self._make_ssh_request(gerrit_command)
            try:
                changes = []
                for line in result.splitlines():
                    if line.startswith('{') and '"type":"stats"' not in line:
                        try:
                            change_data = json.loads(line)
                            # SSH模式特殊处理：添加current_revision字段
                            if 'id' in change_data and 'number' in change_data:
                                change_data['current_revision'] = commit_id
                                change_data['revisions'] = {
                                    commit_id: {
                                        'files': {}  # 初始化为空，后续会填充
                                    }
                                }
                            changes.append(change_data)
                        except json.JSONDecodeError as e:
                            logger.warning(f"JSON解析跳过一行：{line} | 错误：{str(e)}")
                return changes
            except json.JSONDecodeError:
                logger.error(f"gerrit返回输出解析失败:{result}")
                return []
        else:
            url = (
                f"{self.base_url}/a/changes/?q=commit:{commit_id}"
                "&o=ALL_REVISIONS&o=ALL_FILES"
            )
            try:
                response_text = self._make_request("GET", url)
                return json.loads(response_text)
            except Exception as e:
                logger.error(f"Failed to get change metadata: {e}")
                return []

    def _is_supported_file(self, file_path: str):
        """检查文件扩展名是否支持"""
        supported_exts = os.getenv("SUPPORTED_EXTENSIONS", ".c,.rs").split(",")
        return any(file_path.endswith(ext) for ext in supported_exts)

    def get_all_files(self, change_id: str) -> list:
        """获取变更中的所有文件列表"""
        url = f"{self.base_url}/a/changes/{change_id}/revisions/current/files/"
        try:
            response = self._make_request("GET", url)
            return list(json.loads(response).keys())
        except Exception as e:
            logger.error(f"Failed to get all files: {e}")
            return []

    def _get_headers(self):
        """获取带有认证信息的请求头"""
        auth_str = f"{self.username}:{self.token}".encode()
        base64_auth = base64.b64encode(auth_str).decode()
        return {
            "Authorization": f"Basic {base64_auth}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
