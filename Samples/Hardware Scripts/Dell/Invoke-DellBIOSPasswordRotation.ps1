<#
    .SYNOPSIS
    Connects to DeployR from the client side, retrieves the known Dell BIOS password secrets, determines which one (if any) is currently set within the BIOS, and optionally rotates the BIOS password to the newest known secret.

    .DESCRIPTION
    This script answers two questions in order, and only performs a password change when it is explicitly asked to:

    1. Is a Dell BIOS password actually set on this machine?
    2. If one is set, which of the known DeployR secrets is it?

    Workflow:
    1. Detect the execution environment. Windows PE and the full operating system differ in module search locations, elevation requirements, and the availability of the Windows PowerShell compatibility session, so every environment specific decision is driven from a single Switch on the detection result.
    2. Start a transcript beneath the environment appropriate log directory, retaining only the most recent transcripts.
    3. Import the DeployR.Utility module from the locally installed DeployR client and connect to DeployR using the client passcode (explicit parameter first, registry second, passcode file third).
    4. Enumerate the candidate secrets within the DeployR vault. The secret names are discovered through a regular expression against the vault inventory, and the explicit secret name list is only used when the inventory cannot be enumerated. Each secret name is parsed for its version suffix ("-v<Number>"), the unsuffixed name is treated as version 0, and the highest version becomes the target password.
    5. Retrieve each secret value. Values are converted from a SecureString in a way that works on both Windows PowerShell 5.1 and PowerShell 7, they are held in memory only, and they are never written to the transcript.
    6. Resolve the BIOS interface. The Dell WMI-ACPI security namespace ("root\dcim\sysman\wmisecurity") is preferred because it requires no additional module and is available within Windows PE. The DellBIOSProvider module is only used as a fallback and only when it is already present.
    7. Read the current password state. When no password is set there is nothing to identify, and the matched secret is reported as "None".
    8. When a password is set, test each candidate password against the BIOS. The test is a no-op password change (the old password and the new password are the same value), which succeeds only when the supplied password is the one currently set, and which changes nothing when it does.
    9. When the Rotate switch is supplied, change the BIOS password from the identified password to the target password, or set the target password directly when no password is currently set. The result is then verified by re-testing the target password against the BIOS.

    The candidate test order is deliberate. The target (newest) secret is always tested first so that an already rotated machine is identified with a single attempt and requires no further writes, and the remaining candidates are then tested from oldest to newest.

    Successful output resembles the following:

        VERBOSE: Windows PE was not detected. The full operating system code paths will be used.
        VERBOSE: PowerShell version: 7.4.6 [Edition: Core]
        VERBOSE: Attempting to import the DeployR.Utility module. Please Wait... [Path: C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility]
        VERBOSE: Attempting to read the DeployR client passcode from the registry. Please Wait... [Path: HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings]
        VERBOSE: Attempting to connect to DeployR. Please Wait...
        VERBOSE: Successfully connected to DeployR.
        VERBOSE: Discovered 6 candidate secret(s) within the "DeployR" vault. [Secrets: DellBIOSPassword (v0), DellBIOSPassword-v1 (v1), DellBIOSPassword-v2 (v2), DellBIOSPassword-v3 (v3), DellBIOSPassword-v4 (v4), DellBIOSPassword-v5 (v5)]
        VERBOSE: The target secret is "DellBIOSPassword-v5". [Version: 5]
        VERBOSE: Retrieved 6 of 6 candidate secret value(s).
        VERBOSE: The Dell WMI-ACPI security namespace is available. [Namespace: root\dcim\sysman\wmisecurity]
        VERBOSE: The "Admin" BIOS password is currently set. Attempting to determine which known secret matches. Please Wait...
        VERBOSE: Testing candidate 1 of 6. [Secret: DellBIOSPassword-v5]
        VERBOSE: Candidate "DellBIOSPassword-v5" did not match. [Status: 5]
        VERBOSE: Testing candidate 2 of 6. [Secret: DellBIOSPassword]
        VERBOSE: The currently set "Admin" BIOS password matches the "DellBIOSPassword" secret. [Version: 0]
        VERBOSE: Attempting to rotate the "Admin" BIOS password. Please Wait... [From: DellBIOSPassword] [To: DellBIOSPassword-v5]
        VERBOSE: The "Admin" BIOS password was rotated successfully and the new value was verified. [Secret: DellBIOSPassword-v5]
        VERBOSE: Exiting script with exit code 0.

    Exit codes:
        0 - The operation completed successfully.
        1 - An unhandled error occurred.
        2 - The DeployR client, the DeployR connection, or the secret retrieval failed.
        3 - No Dell BIOS interface is available on this system.
        4 - A BIOS password is set, however none of the known secrets matched it.
        5 - The BIOS password change or its verification failed.

    The exit code is returned to the calling process explicitly, so invoke this script with "-File" as shown within the examples. A caller that invokes it with "-Command" must propagate the code itself, because a script exit within a "-Command" host is reported as 1:
        pwsh.exe -ExecutionPolicy Bypass -NoProfile -Command "& '.\Invoke-DellBIOSPasswordRotation.ps1' -Rotate; exit $LASTEXITCODE"

    .PARAMETER Passcode
    The DeployR client passcode. Empty by default and dynamically detected from the registry, then from the passcode file. Explicitly supplying this parameter overrides the dynamic detection.

    .PARAMETER PasscodePath
    The path to a text file containing the DeployR client passcode. Empty by default and dynamically detected as "DeployRPasscode.txt" at the root of the system drive. Only used when the passcode was not supplied and could not be read from the registry.

    .PARAMETER VaultName
    The DeployR secret vault name. The default value is "DeployR", which is the vault shipped with the DeployR server.

    .PARAMETER SecretNameExpression
    A regular expression that determines which secret names within the vault are treated as candidate BIOS passwords. The default expression matches "DellBIOSPassword" and any "DellBIOSPassword-v<Number>" variant.

    .PARAMETER SecretNameList
    An explicit list of candidate secret names. This list is only used when the vault inventory cannot be enumerated, in which case the SecretNameExpression cannot be applied.

    .PARAMETER TargetSecretName
    The secret name holding the password that the BIOS should end up with. Empty by default and dynamically determined as the highest version among the discovered candidates.

    .PARAMETER PasswordType
    The Dell BIOS password to operate against. Valid values are "Admin" and "System". The default value is "Admin".

    .PARAMETER Rotate
    Change the BIOS password to the target secret value. Without this switch the script only reports which secret is currently set and performs no password change. The no-op test used for identification is still performed, because a password cannot be identified without being offered to the BIOS.

    .PARAMETER SkipInitialPasswordSet
    Do not set the target password when no BIOS password is currently set. Only meaningful alongside the Rotate switch.

    .PARAMETER LogDirectory
    The transcript output directory. Empty by default and dynamically determined from the detected environment.

    .PARAMETER TranscriptRetentionCount
    The total number of transcripts to retain within the log directory, including the transcript produced by the current execution. The default value is 3.

    .EXAMPLE
    Report only. Determines whether a BIOS password is set and which known secret it matches, and changes nothing.

    pwsh.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File ".\Invoke-DellBIOSPasswordRotation.ps1"

    .EXAMPLE
    Report and rotate to the newest known secret.

    pwsh.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File ".\Invoke-DellBIOSPasswordRotation.ps1" -Rotate

    .EXAMPLE
    Rotate to an explicitly chosen secret using an explicitly supplied passcode.

    .\Invoke-DellBIOSPasswordRotation.ps1 -Passcode '361717' -TargetSecretName 'DellBIOSPassword-v5' -Rotate

    .EXAMPLE
    Rotate within a Windows PE task sequence using the passcode already present within the boot image registry.

    .\Invoke-DellBIOSPasswordRotation.ps1 -Rotate -Verbose

    .NOTES
    Secret values are never written to the transcript, to the output object, or to any log. Only secret names, versions, and BIOS status codes are recorded.

    The identification test is a password change where the old value and the new value are identical. The BIOS validates the old value before applying the new one, so a matching password results in a status of 0 and no effective change, and a non-matching password results in a non-zero status and no change. This is the only supported way to determine which password is set, because Dell exposes no read operation for the password value itself.

    Dell systems commonly block further password attempts until the next reboot after a small number of consecutive failures within a single boot session. Keep the candidate list short and ordered by likelihood, and expect that a machine holding an unknown password may need a reboot between runs.

    Windows PE requires the WinPE-WMI optional component within the boot image for the Dell WMI-ACPI security namespace to be reachable. Without it, neither this script nor DellBIOSProvider can manage the BIOS password.

    The DellBIOSProvider fallback is only used when the module is already importable. This script never installs it and never stages it, so the only hard requirements are an installed DeployR client and a Dell system exposing its BIOS security namespace.

    .LINK
    https://documentation.2pintsoftware.com/deployr/scripting/scripting-for-osd/set-secret-or-get-secret

    .LINK
    https://www.dell.com/support/kbdoc/en-us/000146401/check-if-a-bios-password-is-set
#>

[CmdletBinding()]
  Param
    (
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('PC')]
        [String]$Passcode,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('PP')]
        [System.IO.FileInfo]$PasscodePath,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('Vault', 'VN')]
        [String]$VaultName = 'DeployR',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('SNE')]
        [Regex]$SecretNameExpression = '^DellBIOSPassword(\-v\d+)?$',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('SNL')]
        [String[]]$SecretNameList = @('DellBIOSPassword', 'DellBIOSPassword-v1', 'DellBIOSPassword-v2', 'DellBIOSPassword-v3', 'DellBIOSPassword-v4', 'DellBIOSPassword-v5'),

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('TSN')]
        [String]$TargetSecretName,

        [Parameter(Mandatory=$False)]
        [ValidateSet('Admin', 'System')]
        [Alias('PT')]
        [String]$PasswordType = 'Admin',

        [Parameter(Mandatory=$False)]
        [Alias('R')]
        [Switch]$Rotate,

        [Parameter(Mandatory=$False)]
        [Alias('SIPS')]
        [Switch]$SkipInitialPasswordSet,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('LD')]
        [System.IO.DirectoryInfo]$LogDirectory,

        [Parameter(Mandatory=$False)]
        [ValidateRange(1, 100)]
        [Alias('TRC')]
        [UInt32]$TranscriptRetentionCount = 3
    )

Try
  {
      #region Define the default action preferences
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'Continue'
      #endregion

      #region Set the default exit code for the script
        [System.Environment]::ExitCode = 0
      #endregion

      #region Determine the script identity
        $ScriptPath = $Null

        Switch ($True)
          {
              {([String]::IsNullOrEmpty($PSCommandPath) -eq $False) -and ([String]::IsNullOrWhiteSpace($PSCommandPath) -eq $False)}
                {
                    $ScriptPath = [System.IO.FileInfo]$PSCommandPath

                    Break
                }

              {([String]::IsNullOrEmpty($MyInvocation.MyCommand.Path) -eq $False) -and ([String]::IsNullOrWhiteSpace($MyInvocation.MyCommand.Path) -eq $False)}
                {
                    $ScriptPath = [System.IO.FileInfo]$MyInvocation.MyCommand.Path

                    Break
                }
          }

        $ScriptBaseName = 'Invoke-DellBIOSPasswordRotation'

        Switch ($Null -ine $ScriptPath)
          {
              {($_ -eq $True)}
                {
                    $ScriptBaseName = $ScriptPath.BaseName
                }
          }
      #endregion

      #region Detect the execution environment and derive every environment specific decision from it
        [Boolean]$IsWindowsPE = ($Null -ine (Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT' -ErrorAction SilentlyContinue)) -or ([System.IO.File]::Exists([System.IO.Path]::Combine("$($Env:SystemRoot)", 'System32', 'winpeshl.exe')))

        $DeployRModulePathList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

        [Boolean]$ElevationRequired = $True
        [Boolean]$WindowsPowerShellCompatibilityAvailable = $True

        Switch ($IsWindowsPE)
          {
              {($_ -eq $True)}
                {
                    Write-Verbose -Message "Windows PE was detected. The Windows PE code paths will be used." -Verbose

                    #Windows PE always executes as the local system account, so there is no elevation to validate, and the Windows PowerShell compatibility session does not exist within a boot image.
                      $ElevationRequired = $False
                      $WindowsPowerShellCompatibilityAvailable = $False

                    Switch ($PSBoundParameters.ContainsKey('LogDirectory'))
                      {
                          {($_ -eq $False)}
                            {
                                $LogDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine("$($Env:SystemDrive)\", 'Windows', 'Temp', 'Logs', 'Software', "$($ScriptBaseName)")
                            }
                      }

                    $DeployRModulePathList.Add([System.IO.Path]::Combine("$($Env:SystemDrive)\", 'Program Files', '2Pint Software', 'DeployR', 'Client', 'PSModules', 'DeployR.Utility'))
                    $DeployRModulePathList.Add([System.IO.Path]::Combine("$($Env:SystemDrive)\", '2Pint', 'DeployR', 'Client', 'PSModules', 'DeployR.Utility'))
                    $DeployRModulePathList.Add([System.IO.Path]::Combine("$($Env:SystemDrive)\", 'DeployR', 'PSModules', 'DeployR.Utility'))
                }

              Default
                {
                    Write-Verbose -Message "Windows PE was not detected. The full operating system code paths will be used." -Verbose

                    Switch ($PSBoundParameters.ContainsKey('LogDirectory'))
                      {
                          {($_ -eq $False)}
                            {
                                $LogDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine("$($Env:SystemRoot)", 'Logs', 'Software', "$($ScriptBaseName)")
                            }
                      }

                    $DeployRModulePathList.Add([System.IO.Path]::Combine("$($Env:ProgramFiles)", '2Pint Software', 'DeployR', 'Client', 'PSModules', 'DeployR.Utility'))
                }
          }

        #The module name is always the final candidate so that an already installed or already imported module is honoured within either environment.
          $DeployRModulePathList.Add('DeployR.Utility')
      #endregion

      #region Validate administrative rights (Windows PE executes as the local system account and requires no validation)
        Switch ($ElevationRequired)
          {
              {($_ -eq $True)}
                {
                    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

                    $Principal = New-Object -TypeName 'System.Security.Principal.WindowsPrincipal' -ArgumentList ($Identity)

                    Switch ($Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
                      {
                          {($_ -eq $False)}
                            {
                                Throw "This script must be run as an administrator."
                            }
                      }
                }
          }
      #endregion

      #region Start the transcript and retain only the most recent transcripts
        Switch ([System.IO.Directory]::Exists($LogDirectory.FullName))
          {
              {($_ -eq $False)}
                {
                    $Null = [System.IO.Directory]::CreateDirectory($LogDirectory.FullName)
                }
          }

        $ExistingTranscriptList = Get-ChildItem -Path ($LogDirectory.FullName) -Filter "$($ScriptBaseName)*.log" -Force -ErrorAction SilentlyContinue | Where-Object {($_ -is [System.IO.FileInfo])} | Sort-Object -Property @('CreationTime') -Descending

        $ExistingTranscriptListCount = ($ExistingTranscriptList | Measure-Object).Count

        For ($ExistingTranscriptListIndex = ($TranscriptRetentionCount - 1); $ExistingTranscriptListIndex -lt $ExistingTranscriptListCount; $ExistingTranscriptListIndex++)
          {
              Try {$Null = $ExistingTranscriptList[$ExistingTranscriptListIndex].Delete()} Catch {}
          }

        $TranscriptPath = [System.IO.FileInfo][System.IO.Path]::Combine($LogDirectory.FullName, "$($ScriptBaseName)_$([DateTime]::Now.ToString('yyyyMMdd-HHmmss')).log")

        $Null = Start-Transcript -Path ($TranscriptPath.FullName) -Force

        [Boolean]$TranscriptStarted = $True

        Write-Verbose -Message "PowerShell version: $($PSVersionTable.PSVersion.ToString()) [Edition: $($PSVersionTable.PSEdition)]" -Verbose
      #endregion

      #region Define the scriptblock that converts a retrieved secret into plain text (Compatible with both Windows PowerShell 5.1 and PowerShell 7)
        $ConvertSecretToPlainText =
          {
              Param
                (
                    [Object]$SecretValue
                )

              $PlainTextValue = $Null

              Switch ($True)
                {
                    {($SecretValue -is [System.Security.SecureString])}
                      {
                          $UnmanagedString = [System.IntPtr]::Zero

                          Try
                            {
                                $UnmanagedString = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretValue)

                                $PlainTextValue = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($UnmanagedString)
                            }
                          Finally
                            {
                                Switch ($UnmanagedString -ine [System.IntPtr]::Zero)
                                  {
                                      {($_ -eq $True)}
                                        {
                                            $Null = [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($UnmanagedString)
                                        }
                                  }
                            }

                          Break
                      }

                    {($SecretValue -is [System.String])}
                      {
                          $PlainTextValue = $SecretValue

                          Break
                      }

                    {($Null -ine $SecretValue)}
                      {
                          $PlainTextValue = $SecretValue.ToString()

                          Break
                      }
                }

              Write-Output -InputObject ($PlainTextValue)
          }
      #endregion

      #region Import the DeployR.Utility module
        [Boolean]$DeployRModuleImported = ($Null -ine (Get-Module -Name 'DeployR.Utility' -ErrorAction SilentlyContinue))

        For ($DeployRModulePathListIndex = 0; $DeployRModulePathListIndex -lt $DeployRModulePathList.Count; $DeployRModulePathListIndex++)
          {
              $DeployRModulePath = $DeployRModulePathList[$DeployRModulePathListIndex]

              [Boolean]$DeployRModuleAvailable = ([System.IO.Directory]::Exists($DeployRModulePath) -eq $True) -or ($Null -ine (Get-Module -ListAvailable -Name ($DeployRModulePath) -ErrorAction SilentlyContinue))

              Switch (($DeployRModuleAvailable -eq $True) -and ($DeployRModuleImported -eq $False))
                {
                    {($_ -eq $True)}
                      {
                          Write-Verbose -Message "Attempting to import the DeployR.Utility module. Please Wait... [Path: $($DeployRModulePath)]" -Verbose

                          $ImportModuleParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                            $ImportModuleParameters.Name = $DeployRModulePath
                            $ImportModuleParameters.Force = $True
                            $ImportModuleParameters.DisableNameChecking = $True
                            $ImportModuleParameters.Verbose = $False

                          $Null = Import-Module @ImportModuleParameters

                          $DeployRModuleImported = $True
                      }
                }
          }

        Switch ($DeployRModuleImported)
          {
              {($_ -eq $False)}
                {
                    [System.Environment]::ExitCode = 2

                    Throw "The DeployR.Utility module could not be found. Please ensure that the DeployR client is installed."
                }
          }
      #endregion

      #region Connect to DeployR using the client passcode (Explicit parameter first, registry second, passcode file third)
        $DeployRGeneralSettingsPath = 'HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings'

        Switch ($PSBoundParameters.ContainsKey('PasscodePath'))
          {
              {($_ -eq $False)}
                {
                    $PasscodePath = [System.IO.FileInfo][System.IO.Path]::Combine("$($Env:SystemDrive)\", 'DeployRPasscode.txt')
                }
          }

        $ClientPasscode = $Null

        Switch ($True)
          {
              {($PSBoundParameters.ContainsKey('Passcode') -eq $True)}
                {
                    Write-Verbose -Message "The explicitly supplied DeployR client passcode will be used." -Verbose

                    $ClientPasscode = $Passcode

                    Break
                }

              {($Null -ine (Get-Item -Path ($DeployRGeneralSettingsPath) -ErrorAction SilentlyContinue))}
                {
                    Write-Verbose -Message "Attempting to read the DeployR client passcode from the registry. Please Wait... [Path: $($DeployRGeneralSettingsPath)]" -Verbose

                    $ClientPasscode = (Get-Item -Path ($DeployRGeneralSettingsPath)).GetValue('ClientPasscode')

                    Break
                }

              {([System.IO.File]::Exists($PasscodePath.FullName))}
                {
                    Write-Verbose -Message "Attempting to read the DeployR client passcode from the passcode file. Please Wait... [Path: $($PasscodePath.FullName)]" -Verbose

                    $ClientPasscode = [System.IO.File]::ReadAllText($PasscodePath.FullName).Trim()

                    Break
                }
          }

        Switch (([String]::IsNullOrEmpty($ClientPasscode) -eq $True) -or ([String]::IsNullOrWhiteSpace($ClientPasscode) -eq $True))
          {
              {($_ -eq $True)}
                {
                    [System.Environment]::ExitCode = 2

                    Throw "The DeployR client passcode could not be determined from the Passcode parameter, the registry, or `"$($PasscodePath.FullName)`"."
                }
          }

        Write-Verbose -Message "Attempting to connect to DeployR. Please Wait..." -Verbose

        Try
          {
              $ConnectDeployRParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                $ConnectDeployRParameters.Passcode = $ClientPasscode
                $ConnectDeployRParameters.ErrorAction = [System.Management.Automation.ActionPreference]::Stop

              $Null = Connect-DeployR @ConnectDeployRParameters
          }
        Catch
          {
              $ConnectionErrorMessage = $_.Exception.Message

              [System.Environment]::ExitCode = 2

              Throw "Unable to connect to DeployR. [Error: $($ConnectionErrorMessage)]"
          }
        Finally
          {
              $ClientPasscode = $Null
          }

        Write-Verbose -Message "Successfully connected to DeployR." -Verbose
      #endregion

      #region Discover the candidate secret names within the DeployR vault
        $SecretVersionExpression = New-Object -TypeName 'System.Text.RegularExpressions.Regex' -ArgumentList @('\-v(?<Version>\d+)$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

        $DiscoveredSecretNameList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

        $SecretInventory = Get-SecretInfo -Vault ($VaultName) -ErrorAction SilentlyContinue | Where-Object {($_.Name -imatch $SecretNameExpression)}

        Switch ((($SecretInventory | Measure-Object).Count -gt 0))
          {
              {($_ -eq $True)}
                {
                    ForEach ($SecretInventoryItem In $SecretInventory)
                      {
                          $DiscoveredSecretNameList.Add($SecretInventoryItem.Name)
                      }
                }

              Default
                {
                    Write-Warning -Message "The `"$($VaultName)`" vault inventory could not be enumerated, or it contained no matching secret names. The explicitly supplied secret name list will be used instead. [Expression: $($SecretNameExpression.ToString())] [Names: $($SecretNameList -Join ', ')]"

                    ForEach ($SecretName In $SecretNameList)
                      {
                          $DiscoveredSecretNameList.Add($SecretName)
                      }
                }
          }

        $UnsortedCandidateList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

        ForEach ($DiscoveredSecretName In ($DiscoveredSecretNameList | Select-Object -Unique))
          {
              $SecretVersionMatch = $SecretVersionExpression.Match($DiscoveredSecretName)

              [UInt32]$SecretVersion = 0

              Switch ($SecretVersionMatch.Success)
                {
                    {($_ -eq $True)}
                      {
                          [UInt32]$SecretVersion = $SecretVersionMatch.Groups['Version'].Value
                      }
                }

              $CandidateProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                $CandidateProperties.SecretName = $DiscoveredSecretName
                $CandidateProperties.Version = $SecretVersion
                $CandidateProperties.Retrieved = $False
                $CandidateProperties.Password = $Null

              $UnsortedCandidateList.Add((New-Object -TypeName 'System.Management.Automation.PSObject' -Property ($CandidateProperties)))
          }

        Switch (($UnsortedCandidateList.Count -eq 0))
          {
              {($_ -eq $True)}
                {
                    [System.Environment]::ExitCode = 2

                    Throw "No candidate BIOS password secrets were found within the `"$($VaultName)`" vault. [Expression: $($SecretNameExpression.ToString())]"
                }
          }

        $CandidateList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

        ForEach ($SortedCandidate In ($UnsortedCandidateList | Sort-Object -Property @('Version')))
          {
              $CandidateList.Add($SortedCandidate)
          }

        $CandidateSummaryList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

        ForEach ($Candidate In $CandidateList)
          {
              $CandidateSummaryList.Add("$($Candidate.SecretName) (v$($Candidate.Version))")
          }

        Write-Verbose -Message "Discovered $($CandidateList.Count) candidate secret(s) within the `"$($VaultName)`" vault. [Secrets: $($CandidateSummaryList -Join ', ')]" -Verbose
      #endregion

      #region Determine the target secret (The newest known password unless one was explicitly supplied)
        $TargetCandidate = $Null

        Switch ($PSBoundParameters.ContainsKey('TargetSecretName'))
          {
              {($_ -eq $True)}
                {
                    $TargetCandidate = $CandidateList | Where-Object {($_.SecretName -ieq $TargetSecretName)} | Select-Object -First 1

                    Switch ($Null -ieq $TargetCandidate)
                      {
                          {($_ -eq $True)}
                            {
                                [System.Environment]::ExitCode = 2

                                Throw "The explicitly supplied target secret `"$($TargetSecretName)`" is not present within the candidate list."
                            }
                      }
                }

              Default
                {
                    $TargetCandidate = $CandidateList | Sort-Object -Property @('Version') -Descending | Select-Object -First 1
                }
          }

        Write-Verbose -Message "The target secret is `"$($TargetCandidate.SecretName)`". [Version: $($TargetCandidate.Version)]" -Verbose
      #endregion

      #region Retrieve the candidate secret values (Values are held in memory only and are never written to the transcript)
        $RetrievedCandidateCount = 0

        For ($CandidateListIndex = 0; $CandidateListIndex -lt $CandidateList.Count; $CandidateListIndex++)
          {
              $Candidate = $CandidateList[$CandidateListIndex]

              Try
                {
                    $SecretValue = Get-Secret -Vault ($VaultName) -Name ($Candidate.SecretName) -ErrorAction Stop

                    $Candidate.Password = $ConvertSecretToPlainText.InvokeReturnAsIs($SecretValue)

                    $Candidate.Retrieved = ($Null -ine $Candidate.Password)

                    Switch ($Candidate.Retrieved)
                      {
                          {($_ -eq $True)}
                            {
                                $RetrievedCandidateCount++
                            }
                      }
                }
              Catch
                {
                    Write-Warning -Message "The `"$($Candidate.SecretName)`" secret could not be retrieved and will be skipped. [Error: $($_.Exception.Message)]"
                }
          }

        Write-Verbose -Message "Retrieved $($RetrievedCandidateCount) of $($CandidateList.Count) candidate secret value(s)." -Verbose

        Switch (($TargetCandidate.Retrieved -eq $False) -and ($Rotate.IsPresent -eq $True))
          {
              {($_ -eq $True)}
                {
                    [System.Environment]::ExitCode = 2

                    Throw "The target secret `"$($TargetCandidate.SecretName)`" could not be retrieved, therefore the rotation cannot be performed."
                }
          }
      #endregion

      #region Resolve the BIOS interface (The Dell WMI-ACPI security namespace is preferred, and DellBIOSProvider is only used when it is already present)
        $WMISecurityNamespace = 'root\dcim\sysman\wmisecurity'

        $BIOSInterface = 'None'

        $ComputerSystem = Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction SilentlyContinue | Select-Object -First 1

        Switch (($Null -ine $ComputerSystem) -and ($ComputerSystem.Manufacturer -inotmatch '.*Dell.*'))
          {
              {($_ -eq $True)}
                {
                    Write-Warning -Message "This system does not report a Dell manufacturer, therefore the Dell BIOS interfaces are unlikely to be available. [Manufacturer: $($ComputerSystem.Manufacturer)]"
                }
          }

        $SecurityInterface = Get-CimInstance -Namespace ($WMISecurityNamespace) -ClassName 'SecurityInterface' -ErrorAction SilentlyContinue | Select-Object -First 1

        Switch ($Null -ine $SecurityInterface)
          {
              {($_ -eq $True)}
                {
                    $BIOSInterface = 'CIM'

                    Write-Verbose -Message "The Dell WMI-ACPI security namespace is available. [Namespace: $($WMISecurityNamespace)]" -Verbose
                }

              Default
                {
                    Write-Warning -Message "The Dell WMI-ACPI security namespace `"$($WMISecurityNamespace)`" is not available. The DellBIOSProvider fallback will be attempted."

                    Switch (($Null -ine (Get-Module -Name 'DellBIOSProvider' -ErrorAction SilentlyContinue)) -or ($Null -ine (Get-Module -ListAvailable -Name 'DellBIOSProvider' -ErrorAction SilentlyContinue)))
                      {
                          {($_ -eq $True)}
                            {
                                $ImportDellBIOSProviderParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                  $ImportDellBIOSProviderParameters.Name = 'DellBIOSProvider'
                                  $ImportDellBIOSProviderParameters.Force = $True
                                  $ImportDellBIOSProviderParameters.DisableNameChecking = $True
                                  $ImportDellBIOSProviderParameters.Verbose = $False
                                  $ImportDellBIOSProviderParameters.ErrorAction = [System.Management.Automation.ActionPreference]::Stop

                                #DellBIOSProvider is a Windows PowerShell edition binary module, therefore PowerShell 7 requires the edition check to be skipped.
                                  Switch ($PSVersionTable.PSVersion.Major -ge 7)
                                    {
                                        {($_ -eq $True)}
                                          {
                                              $ImportDellBIOSProviderParameters.SkipEditionCheck = $True
                                          }
                                    }

                                Try
                                  {
                                      $Null = Import-Module @ImportDellBIOSProviderParameters
                                  }
                                Catch
                                  {
                                      $ImportErrorMessage = $_.Exception.Message

                                      #The Windows PowerShell compatibility session is the last resort, and it only exists outside of Windows PE.
                                        Switch (($PSVersionTable.PSVersion.Major -ge 7) -and ($WindowsPowerShellCompatibilityAvailable -eq $True))
                                          {
                                              {($_ -eq $True)}
                                                {
                                                    Write-Warning -Message "The direct DellBIOSProvider import failed. The Windows PowerShell compatibility session will be attempted. [Error: $($ImportErrorMessage)]"

                                                    $Null = $ImportDellBIOSProviderParameters.Remove('SkipEditionCheck')

                                                    $ImportDellBIOSProviderParameters.UseWindowsPowerShell = $True

                                                    Try {$Null = Import-Module @ImportDellBIOSProviderParameters} Catch {Write-Warning -Message "The DellBIOSProvider compatibility session import failed. [Error: $($_.Exception.Message)]"}
                                                }

                                              Default
                                                {
                                                    Write-Warning -Message "The DellBIOSProvider import failed. [Error: $($ImportErrorMessage)]"
                                                }
                                          }
                                  }

                                Switch (Test-Path -Path 'DellSmbios:\Security' -ErrorAction SilentlyContinue)
                                  {
                                      {($_ -eq $True)}
                                        {
                                            $BIOSInterface = 'Provider'

                                            Write-Verbose -Message "The DellBIOSProvider drive is available. [Path: DellSmbios:\Security]" -Verbose
                                        }
                                  }
                            }

                          Default
                            {
                                Write-Warning -Message "The DellBIOSProvider module is not present on this system, and this script never installs it."
                            }
                      }
                }
          }

        Switch ($BIOSInterface -ieq 'None')
          {
              {($_ -eq $True)}
                {
                    [System.Environment]::ExitCode = 3

                    Throw "No Dell BIOS interface is available on this system. Ensure that the system is a Dell system exposing the `"$($WMISecurityNamespace)`" namespace, and that the WinPE-WMI optional component is present within the boot image when running under Windows PE."
                }
          }
      #endregion

      #region Define the scriptblock that reads the current BIOS password state
        $GetPasswordSetState =
          {
              $PasswordSetState = $Null

              Switch ($BIOSInterface)
                {
                    {($_ -ieq 'CIM')}
                      {
                          $PasswordObject = Get-CimInstance -Namespace ($WMISecurityNamespace) -ClassName 'PasswordObject' -ErrorAction SilentlyContinue | Where-Object {($_.NameId -ieq $PasswordType)} | Select-Object -First 1

                          Switch ($Null -ine $PasswordObject)
                            {
                                {($_ -eq $True)}
                                  {
                                      $PasswordSetState = ([Int]($PasswordObject.IsPasswordSet) -eq 1)
                                  }
                            }

                          Break
                      }

                    {($_ -ieq 'Provider')}
                      {
                          $ProviderStateItem = Get-Item -Path "DellSmbios:\Security\Is$($PasswordType)PasswordSet" -ErrorAction SilentlyContinue

                          Switch ($Null -ine $ProviderStateItem)
                            {
                                {($_ -eq $True)}
                                  {
                                      $PasswordSetState = ("$($ProviderStateItem.CurrentValue)" -imatch '^(True|1|Enabled)$')
                                  }
                            }

                          Break
                      }
                }

              Write-Output -InputObject ($PasswordSetState)
          }
      #endregion

      #region Define the scriptblock that offers a password to the BIOS (An identical old value and new value is a no-op test, and differing values perform the change)
        $SetBIOSPassword =
          {
              Param
                (
                    [String]$OldPassword,
                    [String]$NewPassword
                )

              $OperationProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                $OperationProperties.Successful = $False
                $OperationProperties.Status = -1
                $OperationProperties.Message = ''

              [Boolean]$OldPasswordSupplied = ([String]::IsNullOrEmpty($OldPassword) -eq $False)

              Try
                {
                    Switch ($BIOSInterface)
                      {
                          {($_ -ieq 'CIM')}
                            {
                                $PasswordEncoder = New-Object -TypeName 'System.Text.UTF8Encoding'

                                [Byte[]]$SecurityHandle = $PasswordEncoder.GetBytes($OldPassword)

                                #The security type is 0 when no password is currently set, and 1 when an existing password is being validated or changed.
                                  [UInt32]$SecurityType = 0

                                  Switch ($OldPasswordSupplied)
                                    {
                                        {($_ -eq $True)}
                                          {
                                              [UInt32]$SecurityType = 1
                                          }
                                    }

                                $MethodArguments = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                  $MethodArguments.SecType = [UInt32]$SecurityType
                                  $MethodArguments.SecHndCount = [UInt32]$SecurityHandle.Length
                                  $MethodArguments.SecHandle = [Byte[]]$SecurityHandle
                                  $MethodArguments.NameId = [String]$PasswordType
                                  $MethodArguments.OldPassword = [String]$OldPassword
                                  $MethodArguments.NewPassword = [String]$NewPassword

                                $InvokeCimMethodParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                  $InvokeCimMethodParameters.InputObject = $SecurityInterface
                                  $InvokeCimMethodParameters.MethodName = 'SetNewPassword'
                                  $InvokeCimMethodParameters.Arguments = $MethodArguments
                                  $InvokeCimMethodParameters.ErrorAction = [System.Management.Automation.ActionPreference]::Stop

                                $MethodResult = Invoke-CimMethod @InvokeCimMethodParameters

                                Switch ($True)
                                  {
                                      {($Null -ine $MethodResult) -and ($Null -ine $MethodResult.Status)}
                                        {
                                            $OperationProperties.Status = [Int]($MethodResult.Status)

                                            Break
                                        }

                                      {($Null -ine $MethodResult) -and ($Null -ine $MethodResult.ReturnValue)}
                                        {
                                            $OperationProperties.Status = [Int]($MethodResult.ReturnValue)

                                            Break
                                        }
                                  }

                                $OperationProperties.Successful = ($OperationProperties.Status -eq 0)

                                Break
                            }

                          {($_ -ieq 'Provider')}
                            {
                                $SetItemParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                  $SetItemParameters.Path = "DellSmbios:\Security\$($PasswordType)Password"
                                  $SetItemParameters.Value = $NewPassword
                                  $SetItemParameters.ErrorAction = [System.Management.Automation.ActionPreference]::Stop

                                Switch ($OldPasswordSupplied)
                                  {
                                      {($_ -eq $True)}
                                        {
                                            $SetItemParameters.Password = $OldPassword
                                        }
                                  }

                                $Null = Set-Item @SetItemParameters

                                $OperationProperties.Status = 0
                                $OperationProperties.Successful = $True

                                Break
                            }
                      }
                }
              Catch
                {
                    $OperationProperties.Successful = $False
                    $OperationProperties.Message = $_.Exception.Message
                }

              Write-Output -InputObject (New-Object -TypeName 'System.Management.Automation.PSObject' -Property ($OperationProperties))
          }
      #endregion

      #region Read the current BIOS password state
        $PasswordIsSet = $GetPasswordSetState.InvokeReturnAsIs()

        Switch ($Null -ieq $PasswordIsSet)
          {
              {($_ -eq $True)}
                {
                    [System.Environment]::ExitCode = 3

                    Throw "The current `"$($PasswordType)`" BIOS password state could not be read through the `"$($BIOSInterface)`" interface."
                }
          }
      #endregion

      #region Determine which known secret is currently set within the BIOS
        $MatchedCandidate = $Null

        Switch ($PasswordIsSet)
          {
              {($_ -eq $False)}
                {
                    Write-Verbose -Message "No `"$($PasswordType)`" BIOS password is currently set on this system." -Verbose
                }

              {($_ -eq $True)}
                {
                    Write-Verbose -Message "The `"$($PasswordType)`" BIOS password is currently set. Attempting to determine which known secret matches. Please Wait..." -Verbose

                    #The target secret is tested first so that an already rotated system is identified with a single attempt, and the remaining candidates are then tested from oldest to newest.
                      $TestOrderList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'
                        $TestOrderList.Add($TargetCandidate)

                      ForEach ($Candidate In $CandidateList)
                        {
                            Switch ($Candidate.SecretName -ine $TargetCandidate.SecretName)
                              {
                                  {($_ -eq $True)}
                                    {
                                        $TestOrderList.Add($Candidate)
                                    }
                              }
                        }

                    :CandidateTestLoop For ($TestOrderListIndex = 0; $TestOrderListIndex -lt $TestOrderList.Count; $TestOrderListIndex++)
                      {
                          $Candidate = $TestOrderList[$TestOrderListIndex]

                          $WriteProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                            $WriteProgressParameters.Id = 1
                            $WriteProgressParameters.Activity = "Determining the currently set `"$($PasswordType)`" BIOS password"
                            $WriteProgressParameters.Status = "Testing candidate $($TestOrderListIndex + 1) of $($TestOrderList.Count)"
                            $WriteProgressParameters.CurrentOperation = "Secret: $($Candidate.SecretName)"
                            $WriteProgressParameters.PercentComplete = [System.Math]::Round((($TestOrderListIndex / $TestOrderList.Count) * 100), 2)

                          Write-Progress @WriteProgressParameters

                          Switch ($Candidate.Retrieved)
                            {
                                {($_ -eq $False)}
                                  {
                                      Write-Verbose -Message "Skipping candidate `"$($Candidate.SecretName)`" because its value could not be retrieved." -Verbose

                                      Continue CandidateTestLoop
                                  }
                            }

                          Write-Verbose -Message "Testing candidate $($TestOrderListIndex + 1) of $($TestOrderList.Count). [Secret: $($Candidate.SecretName)]" -Verbose

                          $TestResult = $SetBIOSPassword.InvokeReturnAsIs($Candidate.Password, $Candidate.Password)

                          Switch ($TestResult.Successful)
                            {
                                {($_ -eq $True)}
                                  {
                                      $MatchedCandidate = $Candidate

                                      Write-Verbose -Message "The currently set `"$($PasswordType)`" BIOS password matches the `"$($Candidate.SecretName)`" secret. [Version: $($Candidate.Version)]" -Verbose

                                      Break CandidateTestLoop
                                  }

                                Default
                                  {
                                      $TestFailureDetail = "[Status: $($TestResult.Status)]"

                                      Switch ([String]::IsNullOrEmpty($TestResult.Message))
                                        {
                                            {($_ -eq $False)}
                                              {
                                                  $TestFailureDetail = "$($TestFailureDetail) [Error: $($TestResult.Message)]"
                                              }
                                        }

                                      Write-Verbose -Message "Candidate `"$($Candidate.SecretName)`" did not match. $($TestFailureDetail)" -Verbose
                                  }
                            }
                      }

                    $WriteProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                      $WriteProgressParameters.Id = 1
                      $WriteProgressParameters.Activity = "Determining the currently set `"$($PasswordType)`" BIOS password"
                      $WriteProgressParameters.Completed = $True

                    Write-Progress @WriteProgressParameters

                    Switch ($Null -ieq $MatchedCandidate)
                      {
                          {($_ -eq $True)}
                            {
                                [System.Environment]::ExitCode = 4

                                Write-Warning -Message "A `"$($PasswordType)`" BIOS password is set, however none of the $($CandidateList.Count) known secret(s) matched it. An unknown password is in place on this system."
                            }
                      }
                }
          }
      #endregion

      #region Rotate the BIOS password to the target secret
        [Boolean]$RotationPerformed = $False
        $RotationStatus = 'NotRequested'

        Switch ($Rotate.IsPresent)
          {
              {($_ -eq $False)}
                {
                    Write-Verbose -Message "The Rotate switch was not supplied, therefore no BIOS password change will be performed." -Verbose
                }

              {($_ -eq $True)}
                {
                    Switch ($True)
                      {
                          {($PasswordIsSet -eq $False) -and ($SkipInitialPasswordSet.IsPresent -eq $True)}
                            {
                                $RotationStatus = 'SkippedNoPasswordSet'

                                Write-Verbose -Message "No `"$($PasswordType)`" BIOS password is set and the SkipInitialPasswordSet switch was supplied, therefore no password will be set." -Verbose

                                Break
                            }

                          {($PasswordIsSet -eq $False)}
                            {
                                Write-Verbose -Message "Attempting to set the initial `"$($PasswordType)`" BIOS password. Please Wait... [Secret: $($TargetCandidate.SecretName)]" -Verbose

                                $RotationResult = $SetBIOSPassword.InvokeReturnAsIs('', $TargetCandidate.Password)

                                $RotationPerformed = $RotationResult.Successful

                                Switch ($RotationResult.Successful)
                                  {
                                      {($_ -eq $True)}
                                        {
                                            $RotationStatus = 'InitialPasswordSet'
                                        }

                                      Default
                                        {
                                            $RotationStatus = 'Failed'

                                            [System.Environment]::ExitCode = 5

                                            Write-Warning -Message "The initial `"$($PasswordType)`" BIOS password could not be set. [Secret: $($TargetCandidate.SecretName)] [Status: $($RotationResult.Status)] [Error: $($RotationResult.Message)]"
                                        }
                                  }

                                Break
                            }

                          {($Null -ieq $MatchedCandidate)}
                            {
                                $RotationStatus = 'SkippedUnknownPassword'

                                Write-Warning -Message "The currently set `"$($PasswordType)`" BIOS password is unknown, therefore it cannot be changed. Clear the password manually, or add its value to the `"$($VaultName)`" vault and run this script again."

                                Break
                            }

                          {($MatchedCandidate.SecretName -ieq $TargetCandidate.SecretName)}
                            {
                                $RotationStatus = 'AlreadyCurrent'

                                Write-Verbose -Message "The `"$($PasswordType)`" BIOS password already matches the target secret, therefore no change is required. [Secret: $($TargetCandidate.SecretName)]" -Verbose

                                Break
                            }

                          Default
                            {
                                Write-Verbose -Message "Attempting to rotate the `"$($PasswordType)`" BIOS password. Please Wait... [From: $($MatchedCandidate.SecretName)] [To: $($TargetCandidate.SecretName)]" -Verbose

                                $RotationResult = $SetBIOSPassword.InvokeReturnAsIs($MatchedCandidate.Password, $TargetCandidate.Password)

                                $RotationPerformed = $RotationResult.Successful

                                Switch ($RotationResult.Successful)
                                  {
                                      {($_ -eq $True)}
                                        {
                                            $RotationStatus = 'Rotated'
                                        }

                                      Default
                                        {
                                            $RotationStatus = 'Failed'

                                            [System.Environment]::ExitCode = 5

                                            Write-Warning -Message "The `"$($PasswordType)`" BIOS password could not be rotated. [From: $($MatchedCandidate.SecretName)] [To: $($TargetCandidate.SecretName)] [Status: $($RotationResult.Status)] [Error: $($RotationResult.Message)]"
                                        }
                                  }
                            }
                      }
                }
          }
      #endregion

      #region Verify the result of a performed password change
        Switch ($RotationPerformed)
          {
              {($_ -eq $True)}
                {
                    $PerformedAction = 'rotated'

                    Switch ($RotationStatus -ieq 'InitialPasswordSet')
                      {
                          {($_ -eq $True)}
                            {
                                $PerformedAction = 'set'
                            }
                      }

                    $VerificationResult = $SetBIOSPassword.InvokeReturnAsIs($TargetCandidate.Password, $TargetCandidate.Password)

                    Switch ($VerificationResult.Successful)
                      {
                          {($_ -eq $True)}
                            {
                                $MatchedCandidate = $TargetCandidate

                                $PasswordIsSet = $True

                                Switch ([System.Environment]::ExitCode -eq 4)
                                  {
                                      {($_ -eq $True)}
                                        {
                                            [System.Environment]::ExitCode = 0
                                        }
                                  }

                                Write-Verbose -Message "The `"$($PasswordType)`" BIOS password was $($PerformedAction) successfully and the new value was verified. [Secret: $($TargetCandidate.SecretName)]" -Verbose
                            }

                          Default
                            {
                                $RotationStatus = 'VerificationFailed'

                                [System.Environment]::ExitCode = 5

                                Write-Warning -Message "The `"$($PasswordType)`" BIOS password change reported success, however the new value could not be verified. [Secret: $($TargetCandidate.SecretName)] [Status: $($VerificationResult.Status)] [Error: $($VerificationResult.Message)]"
                            }
                      }
                }
          }
      #endregion

      #region Emit the result (No secret values are included)
        $MatchedSecretName = 'None'
        $MatchedSecretVersion = $Null

        Switch ($Null -ine $MatchedCandidate)
          {
              {($_ -eq $True)}
                {
                    $MatchedSecretName = $MatchedCandidate.SecretName
                    $MatchedSecretVersion = $MatchedCandidate.Version
                }
          }

        $CandidateNameList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

        ForEach ($Candidate In $CandidateList)
          {
              $CandidateNameList.Add($Candidate.SecretName)
          }

        $ResultProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
          $ResultProperties.ComputerName = $Env:ComputerName
          $ResultProperties.Manufacturer = $ComputerSystem.Manufacturer
          $ResultProperties.Model = $ComputerSystem.Model
          $ResultProperties.IsWindowsPE = $IsWindowsPE
          $ResultProperties.BIOSInterface = $BIOSInterface
          $ResultProperties.PasswordType = $PasswordType
          $ResultProperties.PasswordIsSet = $PasswordIsSet
          $ResultProperties.MatchedSecretName = $MatchedSecretName
          $ResultProperties.MatchedSecretVersion = $MatchedSecretVersion
          $ResultProperties.TargetSecretName = $TargetCandidate.SecretName
          $ResultProperties.TargetSecretVersion = $TargetCandidate.Version
          $ResultProperties.CandidateSecretNameList = $CandidateNameList -Join ', '
          $ResultProperties.RotationRequested = $Rotate.IsPresent
          $ResultProperties.RotationStatus = $RotationStatus
          $ResultProperties.TranscriptPath = $TranscriptPath.FullName
          $ResultProperties.ExitCode = [System.Environment]::ExitCode

        $Result = New-Object -TypeName 'System.Management.Automation.PSObject' -Property ($ResultProperties)

        Write-Output -InputObject ($Result)
      #endregion
  }
Catch
  {
      $ErrorRecord = $_

      Switch (([System.Environment]::ExitCode -eq 0))
        {
            {($_ -eq $True)}
              {
                  [System.Environment]::ExitCode = 1
              }
        }

      Write-Warning -Message "Message: $($ErrorRecord.Exception.Message)"
      Write-Warning -Message "Script: $([System.IO.Path]::GetFileName($ErrorRecord.InvocationInfo.ScriptName))"
      Write-Warning -Message "Line Number: $($ErrorRecord.InvocationInfo.ScriptLineNumber)"
      Write-Warning -Message "Line Position: $($ErrorRecord.InvocationInfo.OffsetInLine)"
      Write-Warning -Message "Code: $($ErrorRecord.InvocationInfo.Line)"

      Throw
  }
Finally
  {
      #region Release the retrieved secret values from memory
        Switch ($Null -ine $CandidateList)
          {
              {($_ -eq $True)}
                {
                    ForEach ($Candidate In $CandidateList)
                      {
                          $Candidate.Password = $Null
                      }
                }
          }
      #endregion

      Write-Verbose -Message "Exiting script with exit code $([System.Environment]::ExitCode)." -Verbose

      Switch ($TranscriptStarted)
        {
            {($_ -eq $True)}
              {
                  Try {$Null = Stop-Transcript} Catch {}
              }
        }

      #region Return the exit code to the calling process
        #Setting [System.Environment]::ExitCode alone is not sufficient. A host started with "-File" returns 0 when the script completes and 1 when the script throws, regardless of the value assigned, so the code is explicitly returned here.
          Exit ([System.Environment]::ExitCode)
      #endregion
  }
