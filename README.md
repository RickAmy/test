## 工具简介

本项目基于大模型的自动化代码审查工具进行修改而来，帮助开发团队在代码合并或提交时，快速进行智能化的审查(Code Review)，提升代码质量和开发效率。

## 功能

- 🚀 多模型支持
  - 兼容 DeepSeek、ZhipuAI、OpenAI、通义千问 和 Ollama，想用哪个就用哪个。
- 📢 消息即时推送
  - 审查结果一键直达 钉钉、企业微信 或 飞书，代码问题无处可藏！（暂未实现）
- 📅 自动化日报生成
  - 基于Gerrit记录，自动整理每日开发进展，谁在摸鱼、谁在卷，一目了然 😼。
- 📊 可视化 Dashboard
  - 集中展示所有 Code Review 记录，项目统计、开发者统计，数据说话，甩锅无门！
- 🎭 Review Style 任你选（默认专业型）
  - 专业型 🤵：严谨细致，正式专业。 
  - 讽刺型 😈：毒舌吐槽，专治不服（"这代码是用脚写的吗？"） 
  - 绅士型 🌸：温柔建议，如沐春风（"或许这里可以再优化一下呢~"） 
  - 幽默型 🤪：搞笑点评，快乐改码（"这段 if-else 比我的相亲经历还曲折！"）

## 原理

当用户在 Gerrit上提交代码（git review）时，Gerrit 将自动触发 webhook事件，调用本系统的接口。系统随后通过第三方大模型对代码进行审查，并将审查结果直接反馈到对应的 patchset 的评论中，便于团队查看和处理。

## 部署

### 本地Python环境部署

**1. 获取源码**

```bash
git clone "ssh://liubowen@dev.futlab.me:29418/2030/ai-codereview"
git clone "https://liubowen@dev.futlab.me/gerrit/a/2030/ai-codereview"
```

**2. 安装依赖**

使用 Python 环境（建议使用虚拟环境 venv）安装项目依赖(Python 版本：3.10+，这里必须注意，版本太低无法完成后续编译过程):

```bash
python3.10 -m pip install -r requirements.txt
```

**3. 配置环境变量**

- 编辑 conf/.env 文件，配置以下关键参数：（已经配置为qwen，记得更换相应的API_KEY，测试时仅有十四天的试用期）

```bash
#大模型供应商配置,支持 zhipuai , openai , deepseek 和 ollama
LLM_PROVIDER=deepseek

#DeepSeek
DEEPSEEK_API_KEY={YOUR_DEEPSEEK_API_KEY}

#支持review的文件类型(未配置的文件类型不会被审查)
SUPPORTED_EXTENSIONS=.java,.py,.php,.yml,.vue,.go,.c,.cpp,.h,.js,.css,.md,.sql

#钉钉消息推送: 0不发送钉钉消息,1发送钉钉消息
DINGTALK_ENABLED=0
DINGTALK_WEBHOOK_URL={YOUR_WDINGTALK_WEBHOOK_URL}

#Gitlab配置
GITLAB_ACCESS_TOKEN={YOUR_GITLAB_ACCESS_TOKEN}
```

**4. 启动服务**

- 启动API服务：

```bash
python3.10 api.py
```

- 启动Dashboard服务：

```bash
streamlit run ui.py --server.port=5002 --server.address=0.0.0.0
```
（注意端口5001和5002不要被占用，否则无法启动服务）

### 配置 Gerrit Webhook

在 Gerrit项目设置中，配置 Webhook（需要管理员权限）：

- 克隆项目仓库到本地，（新建）切换到config分支，修改refs/meta/config：

- 确保本地已同步最新分支：
git fetch origin +refs/meta/config:refs/remotes/origin/meta-config

- 编辑webhooks.config添加webhook事件（已添加部分功能，如patchset-created）
vim webhooks.config

- 修改完毕强制推送到refs/meta/config分支
git push origin HEAD:refs/meta/config --force


### 配置消息推送（暂未实现）

#### 1.配置钉钉推送

- 在钉钉群中添加一个自定义机器人，获取 Webhook URL。
- 更新 .env 中的配置：
  ```
  #钉钉配置
  DINGTALK_ENABLED=1  #0不发送钉钉消息，1发送钉钉消息
  DINGTALK_WEBHOOK_URL=https://oapi.dingtalk.com/robot/send?access_token=xxx #替换为你的Webhook URL
  ```

企业微信和飞书推送配置类似，具体参见 [常见问题](doc/faq.md)

## 其它

**1.如何对整个代码库进行Review?**

可以通过命令行工具对整个代码库进行审查。当前功能仍在不断完善中，欢迎试用并反馈宝贵意见！具体操作如下：

```bash
python -m biz.cmd.review
```

运行后，请按照命令行中的提示进行操作即可。
