---
name: git-release
description: >-
  威胁情报项目里程碑发布。当用户要求"发布新版本/打版本/tag/推送/同步到
  Gitee 与 GitHub"或当前工作已形成可交付里程碑时使用。流程包括：确认版本号、
  跑全量测试、更新 docs/开发记录.md、重新生成 PRD docx、打 git tag、
  双远端推送（GitHub origin + Gitee gitee）。版本号与 PRD/开发记录保持一致。
license: MIT
compatibility: opencode
metadata:
  audience: maintainers
  workflow: git
---

## 我的职责

把当前工作固化为一个新的可交付里程碑并双远端发布。本项目是多智能体威胁情报 MVP，
版本节奏为：功能/修复增量 → 次版本（x.Y.z），破坏性架构变更或大功能 → 主版本（X.y.z），
小修/文档 → 补丁（x.y.Z）。版本号必须与 `docs/开发记录.md` 与 PRD docx 封面严格一致。

## 执行前必读

- GitHub 远端名为 `origin`，Gitee 远端名为 `gitee`，主干分支为 `master`。
- GitHub 推送需要代理/VPN（本机网络直连 GitHub 超时），且 Git Credential Manager 会弹出
  交互式登录；Gitee 已存凭据免密。
- 评估证据文件必须入库：`data/benchmark_dataset.json`、`data/ab_eval_result.json`、
  `data/runtime_prompt.json`（`.gitignore` 已白名单放行）。`data/threat_intel.db`、
  `data/llm_cache/`、`.pytest_cache/`、`docx-scripts/node_modules/` 一律不入库。
- 切勿提交：任何 `.env`、`*~$*.docx`（Office 临时锁文件）、`__pycache__`、日志。
- 版本现状（v2.0.0 起锚）：PRD 生成器为 `docx-scripts/generate_doc.js`，输出到项目根
  `项目设计文档_v<版本>.docx`；历史文档归档在 `docs/`。

## 标准发布流程

1. **确认版本号**：查看 `git log --oneline` 与 `git tag --sort=-v:refname`，
   结合 `docs/开发记录.md` 顶部版本段落，与用户确认本次 `MAJOR.MINOR.PATCH`。
2. **跑全量测试**：`D:\Anaconda\python.exe -m pytest tests -q`，全部通过才继续；
   并 `py_compile` 本次改动涉及的 Python 文件。
3. **更新开发记录**：在 `docs/开发记录.md` 顶部追加本次变更（功能/修复/验证结果/文档同步），
   标注日期与版本号。
4. **重新生成 PRD**：按需编辑 `docx-scripts/generate_doc.js` 中的版本号/日期章节，
   然后 `node docx-scripts/generate_doc.js` 生成 `项目设计文档_v<版本>.docx`，并把
   旧版 docx 归档到 `docs/`（命名带日期，原档保留不覆盖）。
5. **同步 README**：如架构/命令有变，更新 README 相应章节。
6. **提交**：按 Conventional Commits 提交一次或多次，`git add -A` 前先
   `git status --porcelain` 检查没有 `~$` 临时文件/`.env`/缓存混入。
7. **打 tag**：`git tag v<版本>`（对齐 PRD 封面版本），并 `git tag -l` 确认。
8. **双远端推送**：
   - `git push gitee master && git push gitee v<版本>`
   - `git push origin master && git push origin v<版本>`
   - 若 GitHub 卡住等认证，提醒用户在弹出的登录窗口完成授权；禁止强杀进程掩盖失败。
9. **验证**：`git log --oneline -1`、`git tag`、`git remote -v`，并确认两平台新版本可见。

## 回滚与补救

- 推送后发现漏提交：补 commit 后 `git push 两个远端 && 推送新 tag`；已推 tag 需修正时用
  `git tag -f` 并 `git push --force-with-lease` 双远端（先征得用户同意）。
- 误提交敏感文件：立即 `git rm --cached` 该文件 + 加入 `.gitignore` + 强推修正，
  并提醒用户到平台上删除历史泄露（这是必须明确告知的风险动作）。
- 任一环节失败：停下并向用户报告失败点与建议命令，不要自行跳过测试直接发布。