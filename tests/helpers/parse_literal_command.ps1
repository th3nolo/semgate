$ErrorActionPreference = 'Stop'
$inputs = [Console]::In.ReadToEnd() | ConvertFrom-Json
$result = foreach ($text in $inputs) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
    [ordered]@{
        errorCount = @($errors).Count
        statementCount = @($ast.EndBlock.Statements).Count
        commandCount = $commands.Count
        elementTypes = @($commands[0].CommandElements | ForEach-Object { $_.GetType().Name })
        values = @($commands[0].CommandElements | ForEach-Object { $_.Value })
    }
}
ConvertTo-Json -InputObject @($result) -Depth 10 -Compress
