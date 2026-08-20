[CmdletBinding()]
param(
    [ValidateRange(1, 300)]
    [int]$PollSeconds = 5,

    [ValidateRange(5, 3600)]
    [int]$MaxResumeDelaySeconds = 120,

    [ValidateRange(1, 100)]
    [int]$MaxAutoResumeAttempts = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utf8Encoding = [System.Text.UTF8Encoding]::new($false)
  [Console]::InputEncoding = $utf8Encoding
  [Console]::OutputEncoding = $utf8Encoding
  $OutputEncoding = $utf8Encoding

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$rulesPath = Join-Path $projectRoot '.codex-automation\planning\RULES.md'
$planPath = Join-Path $projectRoot '.codex-automation\planning\PLAN.md'
$gitReadMaxAttempts = 5

function Get-HerdrErrorCodeFromText {
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    $match = [regex]::Match($Text, '"code"\s*:\s*"(?<code>[^"]+)"')
    if ($match.Success) {
        return $match.Groups['code'].Value
    }

    return $null
}

function Invoke-HerdrText {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [switch]$RetryRead
    )

    $attempt = 0
    while ($true) {
        $attempt++
        $output = & herdr @Arguments 2>&1
        $outputText = $output | Out-String
        if ($LASTEXITCODE -eq 0) {
            return $outputText
        }

        if (-not $RetryRead) {
            throw "Herdr 命令失败: herdr $($Arguments -join ' ')`n$outputText"
        }

        $errorCode = Get-HerdrErrorCodeFromText -Text $outputText
        if (
            [string]::IsNullOrWhiteSpace($errorCode) -or
            $errorCode -notmatch '(?i)(timeout|unavailable|connection|transport|network|server|io)'
        ) {
            throw "Herdr 命令失败: herdr $($Arguments -join ' ')`n$outputText"
        }

        $retryDelaySeconds = [Math]::Min(
            $MaxResumeDelaySeconds,
            $PollSeconds * [Math]::Pow(2, [Math]::Min($attempt - 1, 10))
        )
        Write-Host "Herdr 查询暂时失败，$retryDelaySeconds 秒后重试。" -ForegroundColor Yellow
        Start-Sleep -Seconds ([int]$retryDelaySeconds)
    }
}

function Invoke-HerdrJson {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [switch]$RetryRead
    )

    $outputText = Invoke-HerdrText -Arguments $Arguments -RetryRead:$RetryRead
    try {
        return ($outputText | ConvertFrom-Json -Depth 20)
    }
    catch {
        throw "Herdr 命令未返回有效 JSON: herdr $($Arguments -join ' ')`n$outputText"
    }
}

function Get-HerdrErrorCode {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    return Get-HerdrErrorCodeFromText -Text $ErrorRecord.Exception.Message
}

function Get-TaskAgent {
    param(
        [Parameter(Mandatory)]
        [string]$AgentName
    )

    $agents = Invoke-HerdrJson -Arguments @('agent', 'list') -RetryRead
    return @(
        $agents.result.agents | Where-Object {
            $nameProperty = $_.PSObject.Properties['name']
            $null -ne $nameProperty -and [string]$nameProperty.Value -eq $AgentName
        }
    ) | Select-Object -First 1
}

function Get-AgentPaneId {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Agent
    )

    $paneProperty = $Agent.PSObject.Properties['pane_id']
    if ($null -eq $paneProperty -or [string]::IsNullOrWhiteSpace([string]$paneProperty.Value)) {
        throw 'Herdr 未提供代理 pane ID。'
    }

    return [string]$paneProperty.Value
}

function Assert-TaskAgent {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Agent,

        [Parameter(Mandatory)]
        [string]$AgentName
    )

    $kindProperty = $Agent.PSObject.Properties['agent']
    if ($null -eq $kindProperty -or [string]$kindProperty.Value -ne 'codex') {
        throw "同名代理 $AgentName 不是 Codex 代理，拒绝复用。"
    }

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
        [string]$AgentName
    )

    $agent = Get-TaskAgent -AgentName $AgentName
    if ($null -eq $agent) {
        Write-Host "任务已提交，但代理 $AgentName 已退出，无法确认 pane 归属，保留其 pane。" -ForegroundColor Yellow
        return
    }

    Assert-TaskAgent -Agent $agent -AgentName $AgentName
    $paneId = Get-AgentPaneId -Agent $agent
    try {
        [void](Invoke-HerdrJson -Arguments @('pane', 'close', $paneId))
    }
    catch {
        Write-Host "任务已提交，但关闭 pane $paneId 失败：$($_.Exception.Message)" -ForegroundColor Yellow
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
        '提交消息使用简体中文[：:]\s*(?<subject>[^，。；\r\n]+)'
    )
    if (-not $match.Success) {
        throw "无法从任务 $($Task.id) 提取规定的提交消息。"
    }

    return $match.Groups['subject'].Value.Trim()
}

function Test-GitReadTransientFailure {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )

    return $Text -match '(?i)(cannot be mapped:\s*File too large|cannot allocate memory|not enough memory|paging file is too small|resource temporarily unavailable)'
}

function Invoke-GitRead {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [switch]$RetryTransient
    )

    $gitArguments = @('-C', $projectRoot) + $Arguments
    $attempt = 0
    while ($true) {
        $attempt++
        $output = & git @gitArguments 2>&1
        $exitCode = $LASTEXITCODE
        $outputText = $output | Out-String
        if ($exitCode -eq 0) {
            return @($output)
        }

        $isTransient = Test-GitReadTransientFailure -Text $outputText
        if (-not $RetryTransient -or -not $isTransient -or $attempt -ge $gitReadMaxAttempts) {
            $displayArguments = $gitArguments -join ' '
            throw "Git 读取命令失败（退出码 $exitCode）：git $displayArguments`n$outputText"
        }

        $retryDelaySeconds = [Math]::Min(
            $MaxResumeDelaySeconds,
            $PollSeconds * [Math]::Pow(2, [Math]::Min($attempt - 1, 10))
        )
        Write-Host "Git 读取暂时失败，$retryDelaySeconds 秒后重试；第 $attempt/$gitReadMaxAttempts 次。" -ForegroundColor Yellow
        Start-Sleep -Seconds ([int]$retryDelaySeconds)
    }
}

function Get-CommitSubjects {
    return @(Invoke-GitRead -Arguments @('log', '--format=%s') -RetryTransient)
}

function Test-HeadCommitSubject {
    param(
        [Parameter(Mandatory)]
        [string]$CommitSubject
    )

    $headSubjects = @(Invoke-GitRead -Arguments @('log', '-1', '--format=%s') -RetryTransient)
    return $headSubjects.Count -eq 1 -and $headSubjects[0] -ceq $CommitSubject
}

function Get-NextTask {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Plan
    )

    $commitSubjects = @(Get-CommitSubjects)
    $tasksById = @{}
    foreach ($task in $Plan.tasks) {
        if ($tasksById.ContainsKey($task.id)) {
            throw "PLAN.md 中存在重复任务 ID: $($task.id)"
        }
        $tasksById[$task.id] = $task
    }

    foreach ($task in $Plan.tasks) {
        $subject = Get-TaskCommitSubject -Task $task
        if ($commitSubjects -ccontains $subject) {
            continue
        }

        foreach ($dependencyId in @($task.depends_on)) {
            if (-not $tasksById.ContainsKey($dependencyId)) {
                throw "任务 $($task.id) 依赖不存在的任务 $dependencyId。"
            }

            $dependencySubject = Get-TaskCommitSubject -Task $tasksById[$dependencyId]
            if ($commitSubjects -cnotcontains $dependencySubject) {
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
BREAKPOINT_PROTOCOL=When stopped for a breakpoint, include the dispatcher breakpoint token with value WAIT_FOR_HUMAN on its own line in the final response and do not continue implementation.
FINAL=commit_hash|validations|git_status_short;STOP
"@
}

function Test-AgentBreakpoint {
    param(
        [Parameter(Mandatory)]
        [string]$AgentName
    )

    $recentOutput = Invoke-HerdrText -Arguments @(
        'agent'
        'read'
        $AgentName
        '--source'
        'recent-unwrapped'
        '--lines'
        '120'
    ) -RetryRead
    return $recentOutput -match '(?im)(?:^\s*DISPATCH_BREAKPOINT\s*=\s*WAIT_FOR_HUMAN\s*$|^\s*WAIT_FOR_HUMAN\s*$)'
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
    $breakpointLatched = $false
    $resumePrompt = @"
RESUME_UNTIL_COMMIT=$CommitSubject
IF_NO_BREAKPOINT=IMPLEMENT>VERIFY>STAGE_ALLOWED_ONLY>COMMIT;NO_PLAN_PAUSE
BREAKPOINT=human_action|architecture_ambiguity|permission|requires_out_of_scope;WAIT_IN_PANE;NO_NEXT_TASK
BREAKPOINT_PROTOCOL=When stopped for a breakpoint, include the dispatcher breakpoint token with value WAIT_FOR_HUMAN on its own line in the final response and wait for human input.
"@

    while ($true) {
        if (Test-HeadCommitSubject -CommitSubject $CommitSubject) {
            return
        }

        $agent = Get-TaskAgent -AgentName $AgentName
        if ($null -eq $agent) {
            throw "[$AgentName] 不再存在且未检测到规定提交：$CommitSubject"
        }

        $state = $agent.agent_status
        switch ($state) {
            'working' {
                if ($breakpointLatched) {
                    Write-Host "[$AgentName] 已从人工断点恢复工作，dispatcher 恢复观察。" -ForegroundColor Cyan
                    $breakpointLatched = $false
                    $autoResumeAttempts = 0
                }
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

        if ($breakpointLatched) {
            Start-Sleep -Seconds $PollSeconds
            continue
        }

        if (Test-AgentBreakpoint -AgentName $AgentName) {
            $breakpointLatched = $true
            Write-Host "[$AgentName] 已检测到 DISPATCH_BREAKPOINT=WAIT_FOR_HUMAN，暂停自动续推并等待人工批准。" -ForegroundColor Yellow
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
        Assert-TaskAgent -Agent $existingAgent -AgentName $AgentName
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

    $startedAgent = Get-TaskAgent -AgentName $AgentName
    if ($null -eq $startedAgent) {
        throw "Herdr 已启动 $AgentName，但代理列表中未返回该代理。"
    }

    Assert-TaskAgent -Agent $startedAgent -AgentName $AgentName
    return [pscustomobject]@{
        Agent = $startedAgent
        PaneId = Get-AgentPaneId -Agent $startedAgent
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
    [void](Start-OrReuseTaskAgent -AgentName $agentName -Prompt $prompt)

    Wait-ForTaskOutcome -AgentName $agentName -CommitSubject $commitSubject
    Write-Host "$($task.id) 已检测到规定提交：$commitSubject" -ForegroundColor Green
    Close-TaskPane -AgentName $agentName
}
