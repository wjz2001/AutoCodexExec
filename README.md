# AutoCodexExec
autocodex.py 是一个安全、可断点续跑的 Codex 自动化监督脚本。

## 常用命令

  `python autocodex.py` 启动自动化。已有 .codex-automation/RULES.md、PLAN.md、STATE.md 时，会从第一个未完成任务继续。

  `python autocodex.py --model <模型名> --effort <推理力度>`
      使用指定模型和推理力度启动或续跑。两个参数可以单独使用，命令行值优先于脚本内置默认值
      `--effort` 可选值：low、medium、high、xhigh

  `python autocodex.py --quiet-timeout` 无输出超时秒数
  
  `python autocodex.py --absolute-timeout` 单轮绝对超时秒数
  
  `python autocodex.py --max-failures` 连续失败暂停阈值
  
  `python autocodex.py --max-no-progress` 连续无进展暂停阈值

  `python autocodex.py status` 查看当前状态、任务进度、待处理权限请求

  `python autocodex.py help` 显示本说明

## 首次创建项目

1.  执行 python autocodex.py；
2.  在终端直接粘贴项目需求；
3.  粘贴完成后另起一行只输入 [END] 并按回车；
4.  脚本在 .codex-automation 中生成 RULES.md、PLAN.md、STATE.md，然后逐项执行。

### 停止与续跑

1. 关闭终端或按 Ctrl+C 即停止。再次执行 python autocodex.py 就会根据 .codex-automation/STATE.md 自动续跑；
2. 达到连续失败或无进展阈值时，本次进程会退出，检查原因后直接重新运行即可。

### 完成轮次的处理

  如果三份核心文档都存在、内容非空且任务全部完成，会提供两个选项：
  
  1. 归档：把当前未归档轮次整体移动到 .codex-automation/年月日时分秒/；
  2. 删除：只删除当前未归档轮次，所有已有归档目录保持不变。

  如果三份核心文档缺失、存在空文件或内容无效，则不允许归档，只提供删除选项。

### 权限不足与批准的关系

  1. Codex 始终运行在 workspace-write 沙箱中，不能自行获取更高权限；
  2. 某项操作无法在沙箱内完成时，Codex 只负责写入 PERMISSION_REQUEST.json，然后退出；
  3. 监督脚本停止启动新任务，在当前终端显示选择菜单并等待你的决定，不会自动批准。如果已在脚本顶部填写 WAV Base64，此时会播放声音，并每 5 分钟重复提醒一次。Base64 应放在引号内；
  4. 输入 1 可批准当前任务的一次请求；出现计划级授权选项时，输入 2 可批准当前计划内受项目规则保护的修改；输入 D 拒绝请求。
     选择后仍需按屏幕提示输入完整确认文本，防止模型自动代理自我授权。
  5. 执行结束后请求立即失效，后续即使出现相同命令，也只会产生新的请求并请求重新批准。
  6. Windows 管理员/UAC、凭据输入、系统设置、高成本 API 不会自动执行，只会要求人工处理。

### 授权范围

  1. 脚本依据当前 RULES.md，以及项目目录、子目录和祖先目录中适用的 AGENTS.md，识别明确要求
  修改前必须人工“同意、批准、授权”的规则；
  2.对受项目规则保护的修改，选择 1 只授权当前任务，任务完成后不适用于下一任务；
  3.只有明确选择 2 才授权当前计划内必要的受保护修改，计划级确认需要手动输入 APPROVE PLAN <请求ID>；
  4. PLAN.md、RULES.md 或适用 AGENTS.md 内容变化，以及当前轮次归档或删除后，计划级授权自动失效；
  5. 旧版或规则摘要不匹配的待授权请求会自动失效并归档，再按当前规则生成新请求；
  6. 计划级授权只代表允许工作区内必要的项目代码修改，不包含 danger-full-access、项目外访问、管理员/UAC、凭据、高成本 API、破坏性操作，也不会自动批准后续沙箱外命令；
  7. AUTHORIZATION.json 只由监督脚本写入。工作会话修改或删除它时，监督脚本会立即暂停。

## 运行数据

  .codex-automation/RULES.md                 当前轮次规则
  
  .codex-automation/PLAN.md                  当前轮次计划
  
  .codex-automation/STATE.md                 当前轮次任务状态
  
  .codex-automation/RUN_STATE.json           监督状态
  
  .codex-automation/AUTHORIZATION.json       当前任务或当前计划的项目规则授权
  
  .codex-automation/logs/                    每轮完整日志，包括原始 JSON、完整命令输出和错误细节
  
  .codex-automation/PERMISSION_REQUEST.json  当前待批准请求
  
  .codex-automation/permissions/             已处理请求及结果

## 控制台输出

  控制台只显示经过整理的彩色任务摘要、思考、命令结果、错误末尾，不直接输出 Codex JSON
  
  控制台中省略的完整事件、命令输出、诊断信息始终保存在 .codex-automation/logs/

## Git 忽略规则

  如果脚本同级存在 .gitignore，启动时会自动确保忽略 /.codex-automation/ 和 /autocodex.py

  已存在的规则不会重复添加，如果同级没有 .gitignore，脚本不会主动创建
