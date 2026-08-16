[CmdletBinding()]
param(
    [ValidateRange(1, 300)]
    [int]$PollSeconds = 5,

    [ValidateRange(5, 3600)]
    [int]$MaxResumeDelaySeconds = 120,

    [ValidateRange(1, 100)]
    [int]$MaxAutoResumeAttempts = 5
)

$utf8Encoding = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8Encoding
[Console]::OutputEncoding = $utf8Encoding
$OutputEncoding = $utf8Encoding

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$rulesPath = Join-Path $projectRoot '.codex-automation\planning\RULES.md'
$planPath = Join-Path $projectRoot '.codex-automation\planning\PLAN.md'

function Invoke-HerdrJson {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [switch]$RetryRead
    )

    $attempt = 0
    while ($true) {
        $attempt++
        $output = & herdr @Arguments 2>&1
        if ($LASTEXITCODE -eq 0) {
            return ($output | Out-String | ConvertFrom-Json -Depth 20)
        }

        $outputText = $output | Out-String
        if (-not $RetryRead) {
            throw "Herdr 命令失败: herdr $($Arguments -join ' ')`n$outputText"
        }

        $errorCodeMatch = [regex]::Match($outputText, '"code":"(?<code>[^"]+)"')
        if ($errorCodeMatch.Success) {
            $errorCode = $errorCodeMatch.Groups['code'].Value
            if ($errorCode -notmatch '(?i)(timeout|unavailable|connection|transport|network|server|io)') {
                throw "Herdr 命令失败: herdr $($Arguments -join ' ')`n$outputText"
            }
        }

        $retryDelaySeconds = [Math]::Min(
            $MaxResumeDelaySeconds,
            $PollSeconds * [Math]::Pow(2, [Math]::Min($attempt - 1, 10))
        )
        Write-Host "Herdr 查询暂时失败，$retryDelaySeconds 秒后重试。" -ForegroundColor Yellow
        Start-Sleep -Seconds ([int]$retryDelaySeconds)
    }
}

function Get-HerdrErrorCode {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $match = [regex]::Match($ErrorRecord.Exception.Message, '"code":"(?<code>[^"]+)"')
    if ($match.Success) {
        return $match.Groups['code'].Value
    }

    return $null
}

function Get-TaskAgent {
    param(
        [Parameter(Mandatory)]
        [string]$AgentName
    )

    $agents = Invoke-HerdrJson -Arguments @('agent', 'list') -RetryRead
    return @($agents.result.agents | Where-Object { $_.name -eq $AgentName }) | Select-Object -First 1
}

function Get-AgentPaneId {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Agent
    )

    $paneProperty = $Agent.PSObject.Properties['pane_id']
    if ($null -eq $paneProperty -or [string]::IsNullOrWhiteSpace([string]$paneProperty.Value)) {
        throw "Herdr 未提供代理 $($Agent.name) 的 pane ID。"
    }

    return [string]$paneProperty.Value
}

function Assert-TaskAgentWorkspace {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Agent,

        [Parameter(Mandatory)]
        [string]$AgentName
    )

    $cwdProperty = $Agent.PSObject.Properties['cwd']
    if ($null -eq $cwdProperty -or [string]::IsNullOrWhiteSpace([string]$cwdProperty.Value)) {
        throw "同名代理 $AgentName 已存在，但 Herdr 未提供其工作目录，无法确认是否属于当前项目。"
    }

    $agentCwd = [System.IO.Path]::GetFullPath([string]$cwdProperty.Value).TrimEnd('\', '/')
    $expectedCwd = [System.IO.Path]::GetFullPath($projectRoot).TrimEnd('\', '/')
    if (-not $agentCwd.Equals($expectedCwd, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "同名代理 $AgentName 属于其他工作目录，拒绝复用：$agentCwd"
    }
}

function Close-TaskPane {
    param(
        [Parameter(Mandatory)]
        [string]$PaneId
    )

    try {
        [void](Invoke-HerdrJson -Arguments @('pane', 'close', $PaneId))
    }
    catch {
        Write-Host "任务已提交，但关闭 pane $PaneId 失败：$($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Get-Plan {
    $text = [System.IO.File]::ReadAllText($planPath)
    $startToken = '{PLAN_DATA_START}'
    $endToken = '{PLAN_DATA_END}'
    $start = $text.IndexOf($startToken, [System.StringComparison]::Ordinal)
    $end = $text.IndexOf($endToken, [System.StringComparison]::Ordinal)

    if ($start -lt 0 -or $end -lt 0 -or $end -le $start) {
        throw 'PLAN.md 不包含有效的 PLAN_DATA JSON 数据块。'
    }

    $jsonStart = $start + $startToken.Length
    $json = $text.Substring($jsonStart, $end - $jsonStart).Trim()
    $plan = $json | ConvertFrom-Json -Depth 100
    if ($null -eq $plan.tasks -or $plan.tasks.Count -eq 0) {
        throw 'PLAN.md 不包含任务。'
    }

    return $plan
}

function Get-TaskCommitSubject {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Task
    )

    $text = @($Task.implementation) + @($Task.acceptance) + @($Task.validation) -join "`n"
    $match = [regex]::Match(
        $text,
        '(?<subject>(?:feat|fix|refactor|chore|docs|config|style|perf|test|build|ci)(?:\([^)]+\))?:[^，。；\r\n]+?)(?=\s*提交|[，。；\r\n]|$)'
    )
    if (-not $match.Success) {
        throw "无法从任务 $($Task.id) 提取规定的提交消息。"
    }

    return $match.Groups['subject'].Value.Trim()
}

function Get-CommitSubjects {
    $subjects = & git -C $projectRoot log --format='%s'
    if ($LASTEXITCODE -ne 0) {
        throw '无法读取 Git 提交记录。'
    }

    return @($subjects)
}

function Test-TaskCommitted {
    param(
        [Parameter(Mandatory)]
        [string]$CommitSubject
    )

    return $CommitSubject -in (Get-CommitSubjects)
}

function Get-NextTask {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    $tasksById = @{}
    foreach ($task in $Plan.tasks) {
        if ($tasksById.ContainsKey($task.id)) {
            throw "PLAN.md 中存在重复任务 ID: $($task.id)"
        }
        $tasksById[$task.id] = $task
    }

    foreach ($task in $Plan.tasks) {
        $subject = Get-TaskCommitSubject -Task $task
        if (Test-TaskCommitted -CommitSubject $subject) {
            continue
        }

        foreach ($dependencyId in @($task.depends_on)) {
            if (-not $tasksById.ContainsKey($dependencyId)) {
                throw "任务 $($task.id) 依赖不存在的任务 $dependencyId。"
            }

            $dependencySubject = Get-TaskCommitSubject -Task $tasksById[$dependencyId]
            if (-not (Test-TaskCommitted -CommitSubject $dependencySubject)) {
                throw "任务 $($task.id) 的前置任务 $dependencyId 尚未以规定提交完成。"
            }
        }

        return $task
    }

    return $null
}

function New-TaskPrompt {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Task,

        [Parameter(Mandatory)]
        [string]$CommitSubject
    )

    return @"
EXEC_TASK=$($Task.id)|$($Task.title)
ROOT=$projectRoot
SPEC_RULES=$rulesPath|READ_FULL
SPEC_PLAN=$planPath|READ_JSON_TASK_ONLY:$($Task.id)
CONTRACT=preconditions>implementation>decision_constraints>acceptance>validation
AUTH=IMPLEMENT_NOW;NO_PLAN_PAUSE
SCOPE=allowed_paths_ONLY;PRESERVE_EXISTING_DIRTY;NO_SCOPE_EXPANSION
VERIFY=ALL_SPECIFIED;NO_SKIP
COMMIT=STAGE_ALLOWED_PATHS_ONLY;SUBJECT_EXACT:$CommitSubject
BREAKPOINT=human_action|architecture_ambiguity|permission|requires_out_of_scope;WAIT_IN_PANE;NO_NEXT_TASK
FINAL=commit_hash|validations|git_status_short;STOP
"@
}

function Wait-ForTaskOutcome {
    param(
        [Parameter(Mandatory)]
        [string]$AgentName,

        [Parameter(Mandatory)]
        [string]$CommitSubject
    )

    $autoResumeAttempts = 0
    $lastReportedState = $null
    $settledState = $null
    $settledStateCount = 0
    $resumePrompt = @"
RESUME_UNTIL_COMMIT=$CommitSubject
IF_NO_BREAKPOINT=IMPLEMENT>VERIFY>STAGE_ALLOWED_ONLY>COMMIT;NO_PLAN_PAUSE
BREAKPOINT=human_action|architecture_ambiguity|permission|requires_out_of_scope;WAIT_IN_PANE
"@

    while ($true) {
        if (Test-TaskCommitted -CommitSubject $CommitSubject) {
            return
        }

        $agent = Get-TaskAgent -AgentName $AgentName
        if ($null -eq $agent) {
            throw "[$AgentName] 不再存在且未检测到规定提交：$CommitSubject"
        }

        $state = $agent.agent_status
        switch ($state) {
            'working' {
                $lastReportedState = 'working'
                $settledState = $null
                $settledStateCount = 0
                Start-Sleep -Seconds $PollSeconds
                continue
            }
            'blocked' {
                if ($lastReportedState -ne 'blocked') {
                    Write-Host "[$AgentName] 正在等待批准或回答。dispatcher 不设超时并持续等待。" -ForegroundColor Yellow
                    $lastReportedState = 'blocked'
                }
                $settledState = $null
                $settledStateCount = 0
                Start-Sleep -Seconds $PollSeconds
                continue
            }
            'idle' {
                $settledLabel = '已停止'
            }
            'done' {
                $settledLabel = '已完成当前轮次'
            }
            default {
                if ($lastReportedState -ne $state) {
                    Write-Host "[$AgentName] 当前状态为 $state。dispatcher 不设超时并持续等待。" -ForegroundColor Yellow
                    $lastReportedState = $state
                }
                Start-Sleep -Seconds $PollSeconds
                continue
            }
        }

        if ($settledState -eq $state) {
            $settledStateCount++
        }
        else {
            $settledState = $state
            $settledStateCount = 1
        }

        if ($settledStateCount -lt 2) {
            Start-Sleep -Seconds $PollSeconds
            continue
        }

        if ($autoResumeAttempts -ge $MaxAutoResumeAttempts) {
            Write-Host "[$AgentName] 已达到 $MaxAutoResumeAttempts 次自动续推上限，暂停续推并等待人工操作。" -ForegroundColor Yellow
            Start-Sleep -Seconds $PollSeconds
            continue
        }

        $autoResumeAttempts++
        $resumeDelaySeconds = [Math]::Min(
            $MaxResumeDelaySeconds,
            $PollSeconds * [Math]::Pow(2, [Math]::Min($autoResumeAttempts - 1, 10))
        )
        Write-Host "[$AgentName] ${settledLabel}但未检测到规定提交，正在自动续推；第 $autoResumeAttempts/$MaxAutoResumeAttempts 次，后续等待 $resumeDelaySeconds 秒。" -ForegroundColor Yellow

        try {
            [void](Invoke-HerdrJson -Arguments @('agent', 'prompt', $AgentName, $resumePrompt))
        }
        catch {
            $errorCode = Get-HerdrErrorCode -ErrorRecord $_
            if ($errorCode -notin @('agent_blocked', 'agent_prompt_stalled', 'agent_working')) {
                throw
            }

            Write-Host "[$AgentName] 续推时状态已变化为等待输入或工作中，dispatcher 继续观察。" -ForegroundColor Yellow
        }

        $lastReportedState = $state
        Start-Sleep -Seconds ([int]$resumeDelaySeconds)
    }
}

function Start-OrReuseTaskAgent {
    param(
        [Parameter(Mandatory)]
        [string]$AgentName,

        [Parameter(Mandatory)]
        [string]$Prompt
    )

    $existingAgent = Get-TaskAgent -AgentName $AgentName
    if ($null -ne $existingAgent) {
        Assert-TaskAgentWorkspace -Agent $existingAgent -AgentName $AgentName
        $existingPaneId = Get-AgentPaneId -Agent $existingAgent
        Write-Host "复用现有代理 $AgentName（pane $existingPaneId，状态 $($existingAgent.agent_status)）。" -ForegroundColor Yellow
        return [pscustomobject]@{
            Agent = $existingAgent
            PaneId = $existingPaneId
        }
    }

    $splitArguments = @(
        'pane'
        'split'
        '--current'
        '--direction'
        'right'
        '--cwd'
        $projectRoot
        '--no-focus'
    )
    $split = Invoke-HerdrJson -Arguments $splitArguments
    $paneId = [string]$split.result.pane.pane_id
    if ([string]::IsNullOrWhiteSpace($paneId)) {
        throw "Herdr 未返回 $AgentName 的新 pane ID。"
    }

    $startArguments = @(
        'agent'
        'start'
        $AgentName
        '--kind'
        'codex'
        '--pane'
        $paneId
        '--'
        '--profile'
        'trusted'
    )
    [void](Invoke-HerdrJson -Arguments $startArguments)

    try {
        [void](Invoke-HerdrJson -Arguments @('agent', 'prompt', $AgentName, $Prompt))
    }
    catch {
        $errorCode = Get-HerdrErrorCode -ErrorRecord $_
        if ($errorCode -notin @('agent_blocked', 'agent_prompt_stalled', 'agent_working')) {
            throw
        }

        Write-Host "[$AgentName] 首次提示提交时状态发生变化，dispatcher 转入主循环继续观察。" -ForegroundColor Yellow
    }

    return [pscustomobject]@{
        Agent = Get-TaskAgent -AgentName $AgentName
        PaneId = $paneId
    }
}

if ($env:HERDR_ENV -ne '1') {
    throw 'dispatcher 必须从 Herdr 管理的 pane 内运行。请先在仓库根目录运行 herdr，再在 Herdr pane 中执行此脚本。'
}

foreach ($requiredPath in @($rulesPath, $planPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "缺少必需规划文件: $requiredPath"
    }
}

& herdr --help | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw '无法调用 herdr CLI。'
}

Write-Host 'dispatcher 已启动。任务规则仅从 RULES.md 与 PLAN.md 读取；Git commit subject 是唯一完成信号。' -ForegroundColor Cyan

while ($true) {
    # 每轮重新读取两份规划文件，避免长期运行期间使用过期计划。
    [void][System.IO.File]::ReadAllText($rulesPath)
    $plan = Get-Plan
    $task = Get-NextTask -Plan $plan
    if ($null -eq $task) {
        Write-Host '全部计划任务已按规定提交完成。dispatcher 退出。' -ForegroundColor Green
        break
    }

    $commitSubject = Get-TaskCommitSubject -Task $task
    $agentName = "task-$($task.id.ToLowerInvariant())"
    Write-Host "准备启动 $($task.id)：$($task.title)" -ForegroundColor Cyan

    $prompt = New-TaskPrompt -Task $task -CommitSubject $commitSubject
    $taskAgent = Start-OrReuseTaskAgent -AgentName $agentName -Prompt $prompt
    $paneId = $taskAgent.PaneId

    Wait-ForTaskOutcome -AgentName $agentName -CommitSubject $commitSubject
    Write-Host "$($task.id) 已检测到规定提交：$commitSubject" -ForegroundColor Green
    Close-TaskPane -PaneId $paneId
}
