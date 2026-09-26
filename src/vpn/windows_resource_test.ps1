function Get-TestInventory {
    if ($script:FailureMode -eq 'ObjectNotFound') {
        Write-Error 'Inventory unavailable' -Category ObjectNotFound
        return
    }
    $script:Inventory
    if ($script:FailureMode -eq 'Partial') {
        Write-Error 'Inventory incomplete' -Category PermissionDenied
    }
}

function Get-NetIPAddress {
    [CmdletBinding()]
    param([string]$PolicyStore)
    Get-TestInventory
}

function Get-NetRoute {
    [CmdletBinding()]
    param([string]$PolicyStore)
    Get-TestInventory
}

function New-NetIPAddress {
    [CmdletBinding()]
    param([uint32]$InterfaceIndex, [string]$IPAddress, [byte]$PrefixLength,
          [string]$AddressFamily, [string]$PolicyStore)
    $script:Mutations.Add('create')
}

function New-NetRoute {
    [CmdletBinding()]
    param([uint32]$InterfaceIndex, [string]$DestinationPrefix, [string]$NextHop,
          [uint32]$RouteMetric, [string]$PolicyStore)
    $script:Mutations.Add('create')
}

function Remove-NetIPAddress {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(ValueFromPipeline)]$InputObject)
    process { $script:Mutations.Add("remove:$($InputObject.Id)") }
}

function Remove-NetRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(ValueFromPipeline)]$InputObject)
    process { $script:Mutations.Add("remove:$($InputObject.Id)") }
}

$cases = [Console]::In.ReadToEnd() | ConvertFrom-Json
$results = @(foreach ($case in $cases) {
    $script:Inventory = @($case.Rows)
    $script:FailureMode = $case.FailureMode
    $script:Mutations = [System.Collections.Generic.List[string]]::new()
    $failed = $false
    $output = @()
    try { $output = @(& ([scriptblock]::Create($case.Command))) }
    catch { $failed = $true }
    [pscustomobject]@{
        Failed = $failed
        Output = @($output)
        Mutations = @($script:Mutations.ToArray())
    }
})
ConvertTo-Json -InputObject $results -Depth 8 -Compress
