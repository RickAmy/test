import json
import os
import re
import traceback
from datetime import datetime
from typing import Dict, List
from biz.entity.review_entity import MergeRequestReviewEntity, PushReviewEntity
from biz.event.event_manager import event_manager
from biz.gitlab.webhook_handler import (
    filter_changes,
    MergeRequestHandler,
    PushHandler
)
from biz.github.webhook_handler import (
    filter_changes as filter_github_changes,
    PullRequestHandler as GithubPullRequestHandler,
    PushHandler as GithubPushHandler
)
from biz.service.review_service import ReviewService
from biz.utils.code_reviewer import CodeReviewer
from biz.utils.im import notifier
from biz.utils.log import logger
from biz.gerrit.client import GerritClient
from biz.entity.review_entity import GerritReviewEntity
import time
import pytz

#采用上海时间，而不是默认的世界时间
local_tz = pytz.timezone('Asia/Shanghai')

def handle_push_event(
    webhook_data: dict,
    gitlab_token: str,
    gitlab_url: str,
    gitlab_url_slug: str
):
    push_review_enabled = os.environ.get('PUSH_REVIEW_ENABLED', '0') == '1'
    try:
        handler = PushHandler(webhook_data, gitlab_token, gitlab_url)
        logger.info('Push Hook event received')
        commits = handler.get_push_commits()
        if not commits:
            logger.error('Failed to get commits')
            return

        review_result = None
        score = 0
        additions = 0
        deletions = 0
        if push_review_enabled:
            # 获取PUSH的changes
            changes = handler.get_push_changes()
            logger.info('changes: %s', changes)
            changes = filter_changes(changes)
            if not changes:
                logger.info('未检测到PUSH代码的修改,修改文件可能不满足SUPPORTED_EXTENSIONS。')
            review_result = "关注的文件没有修改"

            if len(changes) > 0:
                commits_text = ';'.join(
                    commit.get('message', '').strip()
                    for commit in commits
                )
                review_result = CodeReviewer().review_and_strip_code(
                    str(changes),
                    commits_text
                )
                score = CodeReviewer.parse_review_score(
                    review_text=review_result
                )
                for item in changes:
                    additions += item['additions']
                    deletions += item['deletions']
            # 将review结果提交到Gitlab的 notes
            handler.add_push_notes(f'Auto Review Result: \n{review_result}')

        event_manager['push_reviewed'].send(PushReviewEntity(
            project_name=webhook_data['project']['name'],
            author=webhook_data['user_username'],
            branch=webhook_data.get('ref', '').replace('refs/heads/', ''),
            # 当前时间
            updated_at=int(datetime.now().timestamp()),
            commits=commits,
            score=score,
            review_result=review_result,
            url_slug=gitlab_url_slug,
            webhook_data=webhook_data,
            additions=additions,
            deletions=deletions,
        ))

    except Exception as e:
        error_message = f'服务出现未知错误: {str(e)}\n{traceback.format_exc()}'
        notifier.send_notification(content=error_message)
        logger.error('出现未知错误: %s', error_message)


def handle_merge_request_event(
    webhook_data: dict,
    gitlab_token: str,
    gitlab_url: str,
    gitlab_url_slug: str
):
    '''
    处理Merge Request Hook事件
    :param webhook_data:
    :param gitlab_token:
    :param gitlab_url:
    :param gitlab_url_slug:
    :return:
    '''
    merge_review_only_protected_branches = (
        os.environ.get('MERGE_REVIEW_ONLY_PROTECTED_BRANCHES_ENABLED', '0')
        == '1'
    )
    try:
        # 解析Webhook数据
        handler = MergeRequestHandler(webhook_data, gitlab_token, gitlab_url)
        logger.info('Merge Request Hook event received')

        # 判断是否为draft（草稿）MR
        object_attributes = webhook_data.get('object_attributes', {})
        is_draft = (
            object_attributes.get('draft')
            or object_attributes.get('work_in_progress')
        )
        if is_draft:
            msg = (
                f"[通知] MR为草稿（draft），未触发AI审查。\n"
                f"项目: {webhook_data['project']['name']}\n"
                f"作者: {webhook_data['user']['username']}\n"
                f"源分支: {object_attributes.get('source_branch')}\n"
                f"目标分支: {object_attributes.get('target_branch')}\n"
                f"链接: {object_attributes.get('url')}"
            )
            notifier.send_notification(content=msg)
            logger.info("MR为draft，仅发送通知，不触发AI review。")
            return

        # 如果开启了仅review projected branches的，判断当前目标分支是否为projected branches
        if (
            merge_review_only_protected_branches
            and not handler.target_branch_protected()
        ):
            logger.info(
                "Merge Request target branch not match "
                "protected branches, ignored."
            )
            return

        if handler.action not in ['open', 'update']:
            logger.info(
                f"Merge Request Hook event, action={handler.action}, "
                "ignored."
            )
            return

        # 检查last_commit_id是否已经存在，如果存在则跳过处理
        last_commit_id = object_attributes.get('last_commit', {}).get('id', '')
        if last_commit_id:
            project_name = webhook_data['project']['name']
            source_branch = object_attributes.get('source_branch', '')
            target_branch = object_attributes.get('target_branch', '')

            if ReviewService.check_mr_last_commit_id_exists(
                project_name,
                source_branch,
                target_branch,
                last_commit_id
            ):
                logger.info(
                    f"Merge Request with last_commit_id {last_commit_id} "
                    f"already exists, skipping review for {project_name}."
                )
                return

        # 仅仅在MR创建或更新时进行Code Review
        # 获取Merge Request的changes
        changes = handler.get_merge_request_changes()
        logger.info('changes: %s', changes)
        changes = filter_changes(changes)
        if not changes:
            logger.info('未检测到有关代码的修改,修改文件可能不满足SUPPORTED_EXTENSIONS。')
            return
        # 统计本次新增、删除的代码总数
        additions = 0
        deletions = 0
        for item in changes:
            additions += item.get('additions', 0)
            deletions += item.get('deletions', 0)

        # 获取Merge Request的commits
        commits = handler.get_merge_request_commits()
        if not commits:
            logger.error('Failed to get commits')
            return

        # review 代码
        commits_text = ';'.join(commit['title'] for commit in commits)
        review_result = CodeReviewer().review_and_strip_code(
            str(changes),
            commits_text
        )

        # 将review结果提交到Gitlab的 notes
        handler.add_merge_request_notes(
            f'Auto Review Result: \n{review_result}'
        )

        # dispatch merge_request_reviewed event
        event_manager['merge_request_reviewed'].send(
            MergeRequestReviewEntity(
                project_name=webhook_data['project']['name'],
                author=webhook_data['user']['username'],
                source_branch=webhook_data['object_attributes'][
                    'source_branch'
                ],
                target_branch=webhook_data['object_attributes'][
                    'target_branch'
                ],
                updated_at=int(datetime.now().timestamp()),
                commits=commits,
                score=CodeReviewer.parse_review_score(
                    review_text=review_result
                ),
                url=webhook_data['object_attributes']['url'],
                review_result=review_result,
                url_slug=gitlab_url_slug,
                webhook_data=webhook_data,
                additions=additions,
                deletions=deletions,
                last_commit_id=last_commit_id,
            )
        )

    except Exception as e:
        error_message = (
            f'AI Code Review 服务出现未知错误: {str(e)}\n'
            f'{traceback.format_exc()}'
        )
        notifier.send_notification(content=error_message)
        logger.error('出现未知错误: %s', error_message)


def handle_github_push_event(
    webhook_data: dict,
    github_token: str,
    github_url: str,
    github_url_slug: str
):
    push_review_enabled = os.environ.get('PUSH_REVIEW_ENABLED', '0') == '1'
    try:
        handler = GithubPushHandler(webhook_data, github_token, github_url)
        logger.info('GitHub Push event received')
        commits = handler.get_push_commits()
        if not commits:
            logger.error('Failed to get commits')
            return

        review_result = None
        score = 0
        additions = 0
        deletions = 0
        if push_review_enabled:
            # 获取PUSH的changes
            changes = handler.get_push_changes()
            logger.info('changes: %s', changes)
            changes = filter_github_changes(changes)
            if not changes:
                logger.info('未检测到PUSH代码的修改,修改文件可能不满足SUPPORTED_EXTENSIONS。')
            review_result = "关注的文件没有修改"

            if len(changes) > 0:
                commits_text = ';'.join(
                    commit.get('message', '').strip()
                    for commit in commits
                )
                review_result = CodeReviewer().review_and_strip_code(
                    str(changes),
                    commits_text
                )
                score = CodeReviewer.parse_review_score(
                    review_text=review_result
                )
                for item in changes:
                    additions += item.get('additions', 0)
                    deletions += item.get('deletions', 0)
            # 将review结果提交到GitHub的 notes
            handler.add_push_notes(f'Auto Review Result: \n{review_result}')

        event_manager['push_reviewed'].send(PushReviewEntity(
            project_name=webhook_data['repository']['name'],
            author=webhook_data['sender']['login'],
            branch=webhook_data['ref'].replace('refs/heads/', ''),
            updated_at=int(datetime.now().timestamp()),  # 当前时间
            commits=commits,
            score=score,
            review_result=review_result,
            url_slug=github_url_slug,
            webhook_data=webhook_data,
            additions=additions,
            deletions=deletions,
        ))

    except Exception as e:
        error_message = f'服务出现未知错误: {str(e)}\n{traceback.format_exc()}'
        notifier.send_notification(content=error_message)
        logger.error('出现未知错误: %s', error_message)


def handle_github_pull_request_event(
    webhook_data: dict,
    github_token: str,
    github_url: str,
    github_url_slug: str
):
    '''
    处理GitHub Pull Request 事件
    :param webhook_data:
    :param github_token:
    :param github_url:
    :param github_url_slug:
    :return:
    '''
    merge_review_only_protected_branches = (
        os.environ.get('MERGE_REVIEW_ONLY_PROTECTED_BRANCHES_ENABLED', '0')
        == '1'
    )
    try:
        # 解析Webhook数据
        handler = GithubPullRequestHandler(
            webhook_data,
            github_token,
            github_url
        )
        logger.info('GitHub Pull Request event received')
        # 如果开启了仅review projected branches的，判断当前目标分支是否为projected branches
        if (
            merge_review_only_protected_branches
            and not handler.target_branch_protected()
        ):
            logger.info(
                "Merge Request target branch not match protected branches, "
                "ignored."
            )
            return

        if handler.action not in ['opened', 'synchronize']:
            logger.info(
                f"Pull Request Hook event, action={handler.action}, ignored."
            )
            return

        # 检查GitHub Pull Request的last_commit_id是否已经存在，如果存在则跳过处理
        github_last_commit_id = webhook_data['pull_request']['head']['sha']
        if github_last_commit_id:
            project_name = webhook_data['repository']['name']
            source_branch = webhook_data['pull_request']['head']['ref']
            target_branch = webhook_data['pull_request']['base']['ref']

            if ReviewService.check_mr_last_commit_id_exists(
                project_name,
                source_branch,
                target_branch,
                github_last_commit_id
            ):
                logger.info(
                    f"Pull Request with last_commit_id "
                    f"{github_last_commit_id} already exists, "
                    f"skipping review for {project_name}."
                )
                return

        # 仅仅在PR创建或更新时进行Code Review
        # 获取Pull Request的changes
        changes = handler.get_pull_request_changes()
        logger.info('changes: %s', changes)
        changes = filter_github_changes(changes)
        if not changes:
            logger.info('未检测到有关代码的修改,修改文件可能不满足SUPPORTED_EXTENSIONS。')
            return
        # 统计本次新增、删除的代码总数
        additions = 0
        deletions = 0
        for item in changes:
            additions += item.get('additions', 0)
            deletions += item.get('deletions', 0)

        # 获取Pull Request的commits
        commits = handler.get_pull_request_commits()
        if not commits:
            logger.error('Failed to get commits')
            return

        # review 代码
        commits_text = ';'.join(commit['title'] for commit in commits)
        review_result = CodeReviewer().review_and_strip_code(
            str(changes),
            commits_text
        )

        # 将review结果提交到GitHub的 notes
        handler.add_pull_request_notes(
            f'Auto Review Result: \n{review_result}'
        )

        # dispatch pull_request_reviewed event
        event_manager['merge_request_reviewed'].send(
            MergeRequestReviewEntity(
                project_name=webhook_data['repository']['name'],
                author=webhook_data['pull_request']['user']['login'],
                source_branch=webhook_data['pull_request']['head']['ref'],
                target_branch=webhook_data['pull_request']['base']['ref'],
                updated_at=int(datetime.now().timestamp()),
                commits=commits,
                score=CodeReviewer.parse_review_score(
                    review_text=review_result
                ),
                url=webhook_data['pull_request']['html_url'],
                review_result=review_result,
                url_slug=github_url_slug,
                webhook_data=webhook_data,
                additions=additions,
                deletions=deletions,
                last_commit_id=github_last_commit_id,
            ))

    except Exception as e:
        error_message = f'服务出现未知错误: {str(e)}\n{traceback.format_exc()}'
        notifier.send_notification(content=error_message)
        logger.error('出现未知错误: %s', error_message)


def handle_gerrit_event(
    data: dict,
    gerrit_token: str = None,
    gerrit_url: str = None,
    url_slug: str = None
) -> bool:
    """接收Gerrit Webhook事件"""
    try:
        # 直接调用处理函数，不使用线程池
        return _process_gerrit_task(
            data=data,
            gerrit_token=gerrit_token or os.getenv('GERRIT_ACCESS_TOKEN'),
            gerrit_url=gerrit_url or os.getenv('GERRIT_BASE_URL'),
            url_slug=url_slug,
            worker_name="Direct-Processor"
        )
    except Exception as e:
        logger.error(f"Gerrit事件处理失败: {str(e)}", exc_info=True)
        return False


def _process_gerrit_task(data: dict, gerrit_token: str, gerrit_url: str, url_slug: str, worker_name: str) -> bool:
    """
    实际处理Gerrit事件的函数（由worker线程调用）
    每个任务独立初始化GerritClient，避免资源竞争
    """
    try:
        # 1. 解析基础数据（与原逻辑一致）
        change = data.get("change", {})
        patch_set = data.get("patchSet", {})
        event_type = data.get("type")
        change_id = change.get("id")
        logger.info(f"{worker_name} 处理Gerrit事件: {event_type}, change_id: {change_id}")
        
        # 2. 验证必要字段（与原逻辑一致）
        required_fields = ['id', 'project', 'branch']
        if not all(change.get(k) for k in required_fields):
            logger.error(f"{worker_name} 缺少必要字段: {required_fields}，跳过处理")
            return False
        if event_type != "patchset-created":
            logger.info(f"{worker_name} 跳过非patchset事件: {event_type}")
            return True
        
        # 3. 独立初始化GerritClient（关键：每个任务独立创建，避免跨线程共享）
        use_ssh = os.getenv('GERRIT_USE_SSH', '1') == '1'
        if use_ssh:
            base_url = os.getenv('GERRIT_SSH_URL', "ssh://aireviewer@10.42.41.50:29418")
        else:
            base_url = gerrit_url or os.getenv('GERRIT_BASE_URL')
        logger.info(f"{worker_name} 初始化Gerrit客户端: use_ssh={use_ssh}, base_url={base_url}")
        
        # 独立创建GerritClient实例（每个任务一个，避免SSH连接冲突）
        gerrit_client = GerritClient(
            base_url=base_url,
            token=gerrit_token,
            username=os.getenv('GERRIT_USERNAME'),
            use_ssh=use_ssh
        )

        # 5. 获取变更详细信息
        revision = patch_set.get("revision")
        if not revision:
            logger.error("Missing revision in patchSet data")
            return False

        # 6. 获取变更内容并过滤文件
        logger.info(f"获取变更内容: {change.get('id')}/{revision}")
        changes = gerrit_client.get_changes(revision, diff_only=True)
        # 开启单独差异评审
        diff_only = True
        if not changes:
            logger.info("未检测到变更内容")
            return True

        # 获取实际文件列表用于验证
        actual_files = [
            change_item.get("filename", "")
            for change_item in changes
            if change_item.get("filename")
        ]
        logger.info(f"实际变更文件: {actual_files}")

        # 过滤支持的文件类型
        filtered_changes = filter_changes(changes)
        if not filtered_changes:
            logger.info("没有支持的文件类型变更")
            return True

        # --------------------------
        # 为过滤后的文件添加「绝对行号标注」
        # 核心逻辑：在代码每一行前添加 [行号] 标记，确保AI直接使用实际行号
        # --------------------------
        logger.info(f"为 {len(filtered_changes)} 个文件添加绝对行号标注...")
        annotated_filtered_changes = []  # 存储带行号标注的变更数据
        for change_item in filtered_changes:
            filename = change_item.get("filename", "unknown")
            # 从diff字段获取完整代码（仅拉取当前提交文件）
            raw_code = change_item.get("diff", "").strip()

            if not raw_code:
                logger.warning(f"文件 {filename} 内容为空，跳过标注")
                annotated_filtered_changes.append(change_item)
                continue

            # 按行拆分代码（保留原始空行，确保行号与本地一致）
            code_lines = raw_code.splitlines()  # splitlines() 会保留空行，行号连续
            annotated_lines = []
            if diff_only:
                current_new_start = None  # 块起始行号（从diff头提取）
                current_actual_line = None  # 跟踪当前实际行号（关键新增变量）
                for line in code_lines:
                    # 1. 解析diff块头（如 @@ -1206,8 +1203,9 @@）
                    if line.startswith('@@'):
                        hunk_match = re.match(r'@@ -\d+,?\d* \+(\d+),?(\d*) @@', line)
                        if hunk_match:
                            current_new_start = int(hunk_match.group(1))  # 块起始行（如1203）
                            current_actual_line = current_new_start  # 初始化实际行号为块起始行
                        annotated_lines.append(line)
                        continue

                    # 2. 处理行号计数：仅上下文行和新增行累加，删除行跳过
                    if current_actual_line is not None:
                        # 忽略删除行（不占用行号）
                        if line.startswith('-'):
                            annotated_lines.append(line)
                            continue
                        # 上下文行（无符号）或新增行（+）：累加实际行号
                        else:
                            # 新增行需要标注行号
                            if line.startswith('+'):
                                annotated_lines.append(f"[{current_actual_line}] {line}")
                            # 上下文行（无符号）：不标注，但占用行号
                            else:
                                annotated_lines.append(line)
                            # 无论上下文行还是新增行，实际行号+1
                            current_actual_line += 1
                    else:
                        # 未解析到块头时，直接保留行
                        annotated_lines.append(line)
            else:
                for line_num, line_content in enumerate(code_lines, start=1):
                    # 标注格式：[行号] 原始代码内容（如 [32] let mut output_file =
                    # File::create(output_path).expect("无法创建输出文件");）
                    annotated_lines.append(f"[{line_num}] {line_content}")

            # 重组标注后的代码，替换原diff字段（不修改其他字段）
            annotated_code = "\n".join(annotated_lines)
            annotated_change_item = change_item.copy()  # 复制原始变更数据
            annotated_change_item["diff"] = annotated_code  # 用带行号的代码覆盖diff字段
            annotated_filtered_changes.append(annotated_change_item)

            # 日志验证：打印前5行标注结果，确认格式正确
            preview_lines = annotated_code.splitlines()[:5]
            logger.debug(
                f"文件 {filename} 标注完成（共{len(code_lines)}行），前5行预览:\n"
                + "\n".join(preview_lines)
            )
        # --------------------------
        # 行号标注逻辑结束
        # --------------------------

        # 7. 初始化GerritReviewEntity（审查前）
        entity = GerritReviewEntity(
            project_name=change.get("project", "unknown"),
            author=data.get("uploader", {}).get("username", "anonymous"),
            branch=change.get("branch"),
            #updated_at=data.get("eventCreatedOn", int(time.time())),
            updated_at=int(datetime.fromtimestamp(
                data.get("eventCreatedOn", time.time()),
                pytz.UTC
            ).astimezone(local_tz).timestamp()),
            commits=[{"message": change.get("commitMessage", "")}],
            score=0,
            review_result="Pending review",
            additions=patch_set.get("sizeInsertions", 0),
            deletions=patch_set.get("sizeDeletions", 0),
            patchset_number=patch_set.get("number", 1),
            change_id=change.get("id"),
            change_url=change.get("url"),
            url_slug=url_slug,
            webhook_data=data
        )

        # 8. 保存初始记录
        ReviewService.insert_gerrit_patchset_review_log(entity)
        logger.info(f"已保存初始记录: {entity.change_id}/{entity.patchset_number}")

        # 9. 执行AI代码审查（传入带行号标注的变更数据）
        logger.info(f"开始AI代码审查: {len(annotated_filtered_changes)}个文件变更")
        try:
            # 记录带行号标注的AI输入内容
            changes_str = str(annotated_filtered_changes)
            logger.debug(f"AI输入内容（前2000字符）: {changes_str[:2000]}...")

            # 记录每个标注文件的详细内容
            for i, change_item in enumerate(annotated_filtered_changes):
                filename = change_item.get("filename", "unknown")
                diff_content = change_item.get("diff", "")
                logger.debug(
                    f"文件 {i+1}: {filename}, 内容长度: {len(diff_content)}"
                )
                logger.debug(f"文件内容预览: {diff_content[:2000]}...")

        except Exception as log_error:
            logger.error(f"记录AI输入内容失败: {log_error}")

        # 调用AI审查
        raw_review_result = CodeReviewer().review_code(
            str(annotated_filtered_changes),
            change.get("commitMessage", "")
        )

        # 先记录原始输出用于调试
        logger.debug(f"AI原始输出: {raw_review_result[:2000]}...")

        # 手动修复常见的JSON格式问题
        fixed_review_result = _fix_json_format(raw_review_result)

        # 然后解析修复后的结果
        review_data = CodeReviewer().parse_structured_review_result(
            fixed_review_result
        )
        score = review_data.get("score", 0)
        summary = review_data.get("summary", "")
        comments = review_data.get("comments", [])

        # 10. 验证和过滤评论中的文件路径
        valid_comments = _validate_comments_with_actual_files(
            comments, actual_files
        )
        # 行号转换函数仅验证文件，不修改行号
        converted_comments = _convert_comment_line_numbers(
            valid_comments, changes
        )
        logger.info(f"有效评论数量: {len(converted_comments)}/{len(comments)}")

        # # 11. 转换分数为Gerrit格式
        # gerrit_score = _convert_to_gerrit_score(score)
        # logger.info(f"分数转换: {score}/100 -> {gerrit_score}")

        # # 12. 更新实体并保存结果
        # entity.review_result = summary
        # entity.score = score  # 保持100分制用于显示
        # #entity.updated_at = int(time.time())
        # entity.updated_at = int(datetime.now(local_tz).timestamp())
        # ReviewService.update_gerrit_patchset_review_log(entity)
        # logger.info("已更新审查结果到数据库")

        # 13. 提交评审到Gerrit（包含行级评论）
        #AI评审结果可能有误，比如返回总分为0，未返回有效行级评论
        # 验证和重试机制
        max_retries = 3
        retry_count = 0
        success = False
        
        while retry_count < max_retries and not success:
            # 验证AI返回的结果是否符合要求
            if not _validate_ai_review_result(summary, converted_comments, score):
                logger.warning(f"AI返回结果不符合要求，尝试重新生成 (尝试 {retry_count + 1}/{max_retries})")
                
                # 重新生成AI审查结果
                new_review_result = _regenerate_ai_review(
                    annotated_filtered_changes, 
                    change.get("commitMessage", ""),
                    summary  # 传入之前的失败结果作为上下文
                )
                
                # 解析新的结果
                new_review_data = CodeReviewer().parse_structured_review_result(new_review_result)
                score = new_review_data.get("score", 0)
                summary = new_review_data.get("summary", "")
                comments = new_review_data.get("comments", [])
                
                # 验证和过滤评论
                valid_comments = _validate_comments_with_actual_files(comments, actual_files)
                converted_comments = _convert_comment_line_numbers(valid_comments, changes)
                
                retry_count += 1
                continue
            
            # 如果验证通过，
            # 转换分数
            gerrit_score = _convert_to_gerrit_score(score)
            
            # 更新实体
            entity.review_result = summary
            entity.score = score
            entity.updated_at = int(datetime.now(local_tz).timestamp())
            ReviewService.update_gerrit_patchset_review_log(entity)
            logger.info(
                f"提交评审到Gerrit: 得分={gerrit_score}, 评论数={len(converted_comments)}"
            )
            #提交到Gerrit
            success = gerrit_client.post_review(
                change_id=entity.change_id,
                revision=revision,
                score=gerrit_score,
                message=f"AI代码审查结果 (得分: {score}/100):{summary}",
                comments=converted_comments
            )
            
            if success:
                break
            else:
                retry_count += 1
                logger.warning(f"提交到Gerrit失败，尝试 {retry_count}/{max_retries}")

        if success:
            logger.info(f"成功处理Gerrit事件: {entity.change_id}")
            return True
        else:
            logger.error(f"提交评审到Gerrit失败: {entity.change_id}")
            return False

    except Exception as e:
        error_msg = f"处理Gerrit事件失败: {str(e)}\n{traceback.format_exc()}"
        logger.error(error_msg)
        # 尝试记录失败状态到数据库
        try:
            if 'entity' in locals():
                entity.review_result = f"Review failed: {str(e)}"
                entity.score = 0
                ReviewService.update_gerrit_patchset_review_log(entity)
        except Exception as db_error:
            logger.error(f"更新数据库失败: {db_error}")
        return False


def _validate_ai_review_result(summary: str, comments: List[Dict], score: int) -> bool:
    """
    验证AI返回的审查结果是否符合要求
    """
    # 检查明显的失败模式：得分为0且没有有效评论
    if score == 0 and (not comments or len(comments) == 0):
        logger.warning(f"AI返回结果异常：得分为0且无有效评论")
        return False
    
    # 检查总结是否为空或过短
    if not summary or len(summary.strip()) < 30:
        logger.warning(f"AI返回的总结过短或为空: '{summary}'")
        return False
    
    # 检查评论是否有效
    valid_comment_count = 0
    for comment in comments:
        if (isinstance(comment, dict) and 
            comment.get("message") and 
            len(comment["message"].strip()) > 5 and
            comment.get("line", 0) > 0 and
            comment.get("file")):
            valid_comment_count += 1
    
    if valid_comment_count == 0:
        logger.warning(f"AI返回结果异常：没有有效评论（原始评论数：{len(comments)}）")
        return False
    
    logger.info(f"AI返回结果验证通过：得分={score}, 有效评论数={valid_comment_count}")
    return True


def _regenerate_ai_review(changes: List[Dict], commit_message: str, previous_failed_result: str = "") -> str:
    """
    重新生成AI审查结果，提供更好的提示
    """
    try:
        reviewer = CodeReviewer()
        
        # 构建增强的提示
        enhanced_prompt = f"""
            请重新审查以下代码变更。之前的审查结果不完整或被截断了，请确保提供完整的代码审查报告，请确保评论部分一定是中文。

            之前的失败结果（仅供参考）:
            {previous_failed_result}

            请确保：
            1. 提供完整的Markdown格式的审查报告
            2. 包含详细的评分明细和总分
            3. 在报告末尾提供完整的JSON格式的结构化数据
            4. 不要截断任何内容
            5. 若token数达到上限，重新开启一个对话进行代码审查
            6. 请确保，对于没有漏洞或者错误的地方不要进行评论

            代码变更内容：
            {str(changes)}

            提交信息：
            {commit_message}
            """
        
        # 使用基础LLM调用而不是完整的review_code方法
        messages = [
            reviewer.prompts["system_message"],
            {
                "role": "user", 
                "content": enhanced_prompt
            }
        ]
        
        return reviewer.call_llm(messages)
    
    except Exception as e:
        logger.error(f"重新生成AI审查失败: {e}")
        return "AI审查生成失败，请人工审查"

# 将100分制转换为Gerrit的-2到+2分制
def _convert_to_gerrit_score(score_100):
    # """将100分制转换为Gerrit的-2到+2分制"""
    # if score_100 >= 90:
    #     return 2
    # elif score_100 >= 80:
    #     return 1
    # elif score_100 >= 70:
    #     return 0
    # elif score_100 >= 60:
    #     return -1
    # else:
    #     return -2
    #暂时保持中性评分
    return 0


def _validate_comments_with_actual_files(comments, actual_files):
    """验证评论文件路径（兼容Gerrit文件路径带/或不带/的情况）"""
    if not comments or not actual_files:
        return []

    valid_comments = []
    actual_file_set = set(actual_files)
    # 额外处理Gerrit可能返回的文件路径前缀（如"/hello.rs"和"hello.rs"视为同一文件）
    actual_file_set_without_prefix = set([f.lstrip('/') for f in actual_files])

    for comment in comments:
        if not isinstance(comment, dict):
            continue
        # 去除路径前缀/，统一匹配
        file_path = comment.get("file", "").lstrip('/')
        line = comment.get("line", 0)
        message = comment.get("message", "").strip()

        # 匹配条件：文件路径在实际文件列表中（含前缀/和不含/两种情况）
        if (file_path in actual_file_set) or (
            file_path in actual_file_set_without_prefix
        ):
            valid_comments.append(comment)
            logger.debug(f"有效行级评论: {file_path}:{line} -> {message[:50]}...")
        else:
            logger.warning(f"跳过不存在的文件评论: {file_path}（实际文件：{actual_files}）")

    return valid_comments


# 修复json格式问题
def _fix_json_format(text):
    """修复常见的JSON格式问题"""
    if not text:
        return text

    # 移除常见的错误前缀
    patterns_to_remove = [
        r'^"json\s*',
        r'^json\s*',
        r'^`+',
        r'^"+\s*',
        r'\s*"+\s*$'
    ]

    fixed_text = text.strip()
    for pattern in patterns_to_remove:
        fixed_text = re.sub(pattern, '', fixed_text, flags=re.IGNORECASE)

    # 修复可能的转义问题
    fixed_text = fixed_text.replace('\\"', '"')
    fixed_text = fixed_text.replace('\\\\', '\\')

    # 确保是有效的JSON
    try:
        # 尝试解析验证
        json.loads(fixed_text)
        logger.info("JSON格式验证通过")
    except json.JSONDecodeError as e:
        logger.warning(f"JSON格式修复后仍然无效: {e}")
        # 尝试提取可能的JSON部分
        json_match = re.search(r'\{.*\}', fixed_text, re.DOTALL)
        if json_match:
            fixed_text = json_match.group(0)
            logger.info(f"提取出可能的JSON部分: {fixed_text[:100]}...")

    return fixed_text


# AI行号与gerrit行号映射
def _convert_comment_line_numbers(
    comments: List[Dict],
    changes: List[Dict]
) -> List[Dict]:
    # 仅验证文件存在性，不做任何行号转换（直接透传AI返回的标注行号）
    valid_comments = []
    existing_files = {
        change["filename"].lstrip('/'): True
        for change in changes if "filename" in change
    }

    for comment in comments:
        if not isinstance(comment, dict):
            continue
        file_path = comment.get("file", "").lstrip('/')
        # AI返回的已是标注的实际行号
        ai_annotated_line = comment.get("line", 0)
        message = comment.get("message", "").strip()

        if file_path in existing_files and ai_annotated_line > 0:
            valid_comments.append({
                "file": file_path,
                "line": ai_annotated_line,  # 直接透传，不修改行号
                "message": message
            })
            logger.debug(
                f"透传实际行号: {file_path}:{ai_annotated_line} → {message[:50]}"
            )
        else:
            logger.warning(f"跳过无效评论: {file_path}:{ai_annotated_line}")

    return valid_comments

