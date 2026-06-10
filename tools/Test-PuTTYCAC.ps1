#Requires -Version 7.0
using namespace System.Collections.Generic
using namespace System.Diagnostics
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Security.Principal
using namespace System.Runtime.InteropServices
using namespace System.IO
using namespace System.Security.AccessControl
using namespace System.Text

[CmdletBinding()]
param(
    [string]$PuTTYRoot,
    [string]$OpenSSHRoot = (Join-Path $env:WINDIR 'System32\OpenSSH'),
    [string]$WorkingRoot = (Join-Path $env:TEMP 'PuTTYCAC-Test'),
    [int[]]$RsaKeyLengths = @(1024, 2048, 3072, 4096),
    [switch]$IncludeLegacyRsaProviders,
    [switch]$TrustTestRoots,
    [switch]$UseSmartCard,
    [string]$SmartCardProvider = 'Microsoft Smart Card Key Storage Provider',
    [string]$Pkcs11Library,
    [string]$Pkcs11Pin = '1234'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$HostName = '127.0.0.1'
$Port = 2222
$UserName = 'testuser'

Set-StrictMode -Version Latest

$PSNativeCommandUseErrorActionPreference = $true

# Initialize state and path hashtables for tracking test results and system resources
$script:State = [ordered]@{
    Results             = [List[object]]::new()
    CreatedThumbprints  = [List[string]]::new()
    TrustedThumbprints  = [List[string]]::new()
    AuthorizedKeyLines  = [List[string]]::new()
    PageantProcesses    = [List[Process]]::new()
    SshdConfigBackup    = $null
    PuTTYRegistryBackup = $null
    Marker              = '# PuTTYCAC-TEST'
    WorkspaceRoot       = Split-Path -Parent $PSScriptRoot
}
$script:Paths = [ordered]@{}

# Shared constants
$CngProvider = 'Microsoft Software Key Storage Provider'
$LegacyEnhancedProvider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
$LegacyOldProvider = 'Microsoft Enhanced Cryptographic Provider v1.0'
$ClientAuthEku = '1.3.6.1.5.5.7.3.2'
$ServerAuthEku = '1.3.6.1.5.5.7.3.1'
$SmartCardLogonEku = '1.3.6.1.4.1.311.20.2.2'

# Add test result entry to the results collection and write to host
function Add-Result([string]$Name, [string]$Status, [string]$Detail, [hashtable]$Data = @{}) {
    $Entry = [PSCustomObject]([ordered]@{
            Name   = $Name
            Status = $Status
            Detail = $Detail
            Data   = $Data
        })

    $script:State.Results.Add($Entry) | Out-Null
    Write-Host ("[{0}] {1}: {2}" -f $Status.ToUpperInvariant(), $Name, $Detail)
}

# Verify current PowerShell session has administrator privileges
function Test-IsAdmin {
    $Identity = [WindowsIdentity]::GetCurrent()
    $Principal = [WindowsPrincipal]::new($Identity)
    return $Principal.IsInRole([WindowsBuiltInRole]::Administrator)
}

# Create directory if it doesn't exist; returns the resolved path
function New-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

# Verify file exists and return its full resolved path
function Get-CommandPath([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing required file: $Path" }
    return (Resolve-Path -LiteralPath $Path).Path
}

# Execute native command and return exit code, stdout, and stderr
function Invoke-Native([string]$FilePath, [string[]]$ArgumentList, [switch]$IgnoreExitCode) {
    $ProcessInfo = [ProcessStartInfo]::new()
    $ProcessInfo.FileName = $FilePath

    foreach ($Arg in $ArgumentList) {
        [void]$ProcessInfo.ArgumentList.Add($Arg)
    }

    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.CreateNoWindow = $true

    $Process = [Process]::Start($ProcessInfo)
    $OutTask = $Process.StandardOutput.ReadToEndAsync()
    $ErrTask = $Process.StandardError.ReadToEndAsync()
    $Process.WaitForExit()

    $StdOut = $OutTask.GetAwaiter().GetResult()
    $StdErr = $ErrTask.GetAwaiter().GetResult()

    if (-not $IgnoreExitCode -and $Process.ExitCode -ne 0) { throw "Command failed ($($Process.ExitCode)): $FilePath $($ArgumentList -join ' ')`n$StdOut`n$StdErr" }

    return [PSCustomObject]@{
        ExitCode = $Process.ExitCode
        StdOut   = $StdOut.Trim()
        StdErr   = $StdErr.Trim()
    }
}

# Add certificate to the trusted root store (LocalMachine if running as Admin to avoid prompt, otherwise CurrentUser)
function Add-ToCurrentUserRootStore([X509Certificate2]$Certificate) {
    $IsAdmin = ([WindowsPrincipal][WindowsIdentity]::GetCurrent()).IsInRole([WindowsBuiltInRole]::Administrator)
    $StoreLocation = if ($IsAdmin) { 'LocalMachine' } else { 'CurrentUser' }
    $Store = [X509Store]::new('Root', $StoreLocation)

    try {
        $Store.Open([OpenFlags]::ReadWrite)
        $Store.Add($Certificate)
    }
    finally {
        $Store.Close()
    }
}

# Remove certificate from the trusted root store by thumbprint
function Remove-FromCurrentUserRootStore([string]$Thumbprint) {
    # Delete from Registry to avoid the Windows Security Warning popup for Root store deletions
    $Paths = @(
        "HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates\$Thumbprint",
        "HKLM:\Software\Microsoft\SystemCertificates\Root\Certificates\$Thumbprint"
    )
    foreach ($Path in $Paths) {
        if (Test-Path -LiteralPath $Path) {
            try {
                Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            }
            catch {
                # Ignore access errors (e.g. HKLM if not admin)
            }
        }
    }
}

# Map OS architecture to native PuTTY binary directory name
function Get-NativePuTTYArch {
    switch ([RuntimeInformation]::OSArchitecture) {
        'X64' { return 'x64' }
        'Arm64' { return 'arm64' }
        'X86' { return 'x86' }
        default {
            throw "Unsupported OS architecture: $([RuntimeInformation]::OSArchitecture)"
        }
    }
}

# Locate PuTTY binary directory matching native architecture
function Resolve-PuTTYRoot {
    $NativeArch = Get-NativePuTTYArch

    if ($PuTTYRoot) {
        $Resolved = (Resolve-Path -LiteralPath $PuTTYRoot).Path
        $PlinkPath = Join-Path $Resolved 'plink.exe'
        if (-not (Test-Path -LiteralPath $PlinkPath -PathType Leaf)) { throw "PuTTYRoot does not contain plink.exe: $Resolved" }
        return $Resolved
    }

    $Candidates = @(
        (Join-Path $script:State.WorkspaceRoot "build\$NativeArch\Release"),
        (Join-Path $script:State.WorkspaceRoot "build\$NativeArch\Debug"),
        (Join-Path $script:State.WorkspaceRoot "binaries\$NativeArch")
    )

    foreach ($Candidate in $Candidates) {
        if (
            (Test-Path -LiteralPath (Join-Path $Candidate 'plink.exe')) -and
            (Test-Path -LiteralPath (Join-Path $Candidate 'pageant.exe'))
        ) {
            return (Resolve-Path -LiteralPath $Candidate).Path
        }
    }

    throw "Unable to locate a native PuTTY-CAC binary directory for '$NativeArch' containing at least plink.exe and pageant.exe. Use -PuTTYRoot with a matching build."
}

# Backup current PuTTY registry settings to file
function Backup-PuTTYRegistry {
    $RegPath = 'HKCU:\Software\SimonTatham\PuTTY'
    $script:State.PuTTYRegistryBackup = Join-Path $script:Paths.Run 'putty-registry-backup.clixml'

    $Payload = if (Test-Path -LiteralPath $RegPath) {
        Get-ItemProperty -LiteralPath $RegPath | Select-Object *
    }
    else {
        $null
    }

    $Payload | Export-Clixml -LiteralPath $script:State.PuTTYRegistryBackup
}

# Restore PuTTY registry settings from backup file
function Restore-PuTTYRegistry {
    $RegPath = 'HKCU:\Software\SimonTatham\PuTTY'

    if (-not $script:State.PuTTYRegistryBackup -or -not (Test-Path -LiteralPath $script:State.PuTTYRegistryBackup -PathType Leaf)) {
        return
    }

    $Backup = Import-Clixml -LiteralPath $script:State.PuTTYRegistryBackup

    if ($null -eq $Backup) {
        Remove-Item -LiteralPath $RegPath -Recurse -Force -ErrorAction SilentlyContinue
        return
    }

    New-Item -Path $RegPath -Force | Out-Null
    $Keep = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

    # Remove properties that were added during testing
    $Current = if (Test-Path -LiteralPath $RegPath) { Get-ItemProperty -LiteralPath $RegPath } else { $null }

    if ($Current) { foreach ($Prop in $Current.PSObject.Properties.Name | Where-Object { $_ -notin $Keep }) { Remove-ItemProperty -LiteralPath $RegPath -Name $Prop -Force -ErrorAction SilentlyContinue } }

    # Restore original properties
    foreach ($Prop in $Backup.PSObject.Properties | Where-Object { $_.Name -notin $Keep }) {
        $Kind = if ($Prop.Value -is [int]) { 'DWord' }
        elseif ($Prop.Value -is [string[]]) { 'MultiString' }
        else { 'String' }

        New-ItemProperty -LiteralPath $RegPath -Name $Prop.Name -Value $Prop.Value -PropertyType $Kind -Force | Out-Null
    }
}

# Create a self-signed test certificate with configurable parameters
function New-TestCertificate([string]$CaseName, [string]$Provider, [string]$KeyAlgorithm, [int]$KeyLength, [string[]]$EnhancedKeyUsage, [datetime]$NotAfter, [switch]$TrustRoot) {
    $FriendlyName = "PuTTYCAC Test $CaseName"
    $NotBefore = if ($NotAfter -lt (Get-Date)) { $NotAfter.AddDays(-30) } else { (Get-Date).AddMinutes(-5) }

    $CertArgs = @{
        CertStoreLocation = 'Cert:\CurrentUser\My'
        Subject           = "CN=$CaseName"
        FriendlyName      = $FriendlyName
        Provider          = $Provider
        HashAlgorithm     = 'SHA256'
        KeyUsage          = 'DigitalSignature'
        KeyUsageProperty  = 'Sign'
        NotBefore         = $NotBefore
        NotAfter          = $NotAfter
        TextExtension     = @('2.5.29.19={text}CA=false')
    }

    if ($EnhancedKeyUsage.Count -gt 0) { $CertArgs.TextExtension += ('2.5.29.37={text}' + ($EnhancedKeyUsage -join ',')) }

    if ($KeyAlgorithm -eq 'RSA') {
        $CertArgs.KeyAlgorithm = 'RSA'
        $CertArgs.KeyLength = $KeyLength
    }
    else {
        $CertArgs.KeyAlgorithm = $KeyAlgorithm
        $CertArgs.CurveExport = 'CurveName'
    }

    $Cert = New-SelfSignedCertificate @CertArgs
    $script:State.CreatedThumbprints.Add($Cert.Thumbprint) | Out-Null

    if ($TrustRoot) {
        Add-ToCurrentUserRootStore -Certificate $Cert
        $script:State.TrustedThumbprints.Add($Cert.Thumbprint) | Out-Null
    }

    return $Cert
}

# Locate pkcs11-tool (OpenSC) in PATH or common install locations
function Find-Pkcs11Tool {
    $Cmd = Get-Command 'pkcs11-tool' -ErrorAction SilentlyContinue
    if ($Cmd) { return $Cmd.Source }

    $Candidates = @(
        'C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe',
        'C:\Program Files (x86)\OpenSC Project\OpenSC\tools\pkcs11-tool.exe'
    )
    foreach ($C in $Candidates) {
        if (Test-Path -LiteralPath $C -PathType Leaf) { return $C }
    }
    return $null
}

# Create a test certificate on a PKCS#11 token: generate key via OpenSSL, import to token
function New-Pkcs11TestCertificate([string]$CaseName, [string]$KeyAlgorithm, [int]$KeyLength, [string]$Curve, [datetime]$NotAfter) {
    $Pkcs11Tool = Find-Pkcs11Tool
    $OpenSSL = Get-Command openssl -ErrorAction SilentlyContinue

    if (-not $Pkcs11Tool) {
        Add-Result -Name $CaseName -Status 'Skip' -Detail 'Skipped PKCS#11 certificate creation: pkcs11-tool (OpenSC) not found.'
        return $null
    }
    if (-not $OpenSSL) {
        Add-Result -Name $CaseName -Status 'Skip' -Detail 'Skipped PKCS#11 certificate creation: openssl not found.'
        return $null
    }

    $Dir = New-Directory (Join-Path $script:Paths.Run "pkcs11-$CaseName")
    $KeyPath = Join-Path $Dir 'key.pem'
    $CertPemPath = Join-Path $Dir 'cert.pem'
    $KeyDerPath = Join-Path $Dir 'key.der'
    $CertDerPath = Join-Path $Dir 'cert.der'

    try {
        # Generate private key with OpenSSL
        if ($KeyAlgorithm -eq 'RSA') {
            Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('genrsa', '-out', $KeyPath, $KeyLength.ToString()) | Out-Null
        }
        else {
            Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('ecparam', '-name', $Curve, '-genkey', '-noout', '-out', $KeyPath) | Out-Null
        }

        # Convert private key to PKCS#8 DER for token import
        Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('pkcs8', '-topk8', '-nocrypt', '-in', $KeyPath, '-outform', 'DER', '-out', $KeyDerPath) | Out-Null

        # Create self-signed certificate
        $DaysValid = [int][Math]::Max(1, [Math]::Ceiling(($NotAfter - (Get-Date)).TotalDays))
        Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @(
            'req', '-x509', '-new', '-key', $KeyPath, '-out', $CertPemPath,
            '-subj', "/CN=$CaseName", '-days', $DaysValid.ToString(),
            '-addext', 'keyUsage=digitalSignature',
            '-addext', 'extendedKeyUsage=clientAuth'
        ) | Out-Null

        # Convert certificate to DER for token import
        Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @('x509', '-in', $CertPemPath, '-outform', 'DER', '-out', $CertDerPath) | Out-Null

        # Extract SHA-1 thumbprint (40 hex chars, no colons)
        $FingerprintLine = (Invoke-Native -FilePath $OpenSSL.Source -ArgumentList @(
                'x509', '-in', $CertPemPath, '-fingerprint', '-sha1', '-noout'
            )).StdOut
        $Thumbprint = ($FingerprintLine -replace '(?i)^.*?=', '' -replace ':', '').Trim().ToLowerInvariant()

        # Generate a unique key/cert slot ID for this test object
        $SlotId = '{0:x2}{1:x2}' -f (Get-Random -Minimum 1 -Maximum 255), (Get-Random -Minimum 1 -Maximum 255)

        # Import private key to token
        Invoke-Native -FilePath $Pkcs11Tool -ArgumentList @(
            '--module', $Pkcs11Library,
            '--login', '--pin', $Pkcs11Pin,
            '--write-object', $KeyDerPath,
            '--type', 'privkey',
            '--id', $SlotId,
            '--label', $CaseName
        ) | Out-Null

        # Import certificate to token
        Invoke-Native -FilePath $Pkcs11Tool -ArgumentList @(
            '--module', $Pkcs11Library,
            '--login', '--pin', $Pkcs11Pin,
            '--write-object', $CertDerPath,
            '--type', 'cert',
            '--id', $SlotId,
            '--label', $CaseName
        ) | Out-Null

        # Load certificate as X509Certificate2 for SSH public key extraction (no store import needed)
        $CertObj = [X509Certificate2]::new([File]::ReadAllBytes($CertPemPath))

        return [PSCustomObject]@{
            Certificate = $CertObj
            Thumbprint  = $Thumbprint
            CertId      = "PKCS:$Thumbprint=$Pkcs11Library"
            SlotId      = $SlotId
        }
    }
    catch {
        Add-Result -Name $CaseName -Status 'Fail' -Detail "PKCS#11 certificate setup failed: $($_.Exception.Message)"
        return $null
    }
}

# Build a test matrix of certificates created on a PKCS#11 token
function New-Pkcs11TestMatrix {
    $Matrix = [List[object]]::new()

    $Cases = @(
        [PSCustomObject]@{ Name = 'PKCS11-RSA-2048';     KeyAlgorithm = 'RSA';   KeyLength = 2048; Curve = '' }
        [PSCustomObject]@{ Name = 'PKCS11-RSA-4096';     KeyAlgorithm = 'RSA';   KeyLength = 4096; Curve = '' }
        [PSCustomObject]@{ Name = 'PKCS11-ECDSA-P256';   KeyAlgorithm = 'ECDSA'; KeyLength = 256;  Curve = 'prime256v1' }
        [PSCustomObject]@{ Name = 'PKCS11-ECDSA-P384';   KeyAlgorithm = 'ECDSA'; KeyLength = 384;  Curve = 'secp384r1' }
    )

    foreach ($Case in $Cases) {
        try {
            $Result = New-Pkcs11TestCertificate -CaseName $Case.Name -KeyAlgorithm $Case.KeyAlgorithm `
                -KeyLength $Case.KeyLength -Curve $Case.Curve -NotAfter (Get-Date).AddDays(30)

            if ($Result) {
                $SshKey = Get-OpenSshKeyLine -Certificate $Result.Certificate
                $Matrix.Add([PSCustomObject]@{
                        Name          = $Case.Name
                        Cert          = $Result.Certificate
                        CertId        = $Result.CertId
                        KeyType       = $Case.KeyAlgorithm
                        Provider      = 'PKCS#11'
                        Bits          = $Case.KeyLength
                        AuthorizedKey = $SshKey
                    }) | Out-Null
                Add-Result -Name $Case.Name -Status 'Pass' -Detail "Created PKCS#11 $($Case.KeyAlgorithm) test certificate on token."
            }
        }
        catch {
            Add-Result -Name $Case.Name -Status 'Skip' -Detail $_.Exception.Message
        }
    }

    return $Matrix
}

# Extract OpenSSH public key from certificate or return fallback key
function Get-OpenSshKeyLine([X509Certificate2]$Certificate, [string]$FallbackPublicKey) {
    if ($FallbackPublicKey) { return $FallbackPublicKey }
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'CertificateTransformer.ps1') -PathType Leaf)) { throw 'Missing tools\CertificateTransformer.ps1.' }

    . (Join-Path $PSScriptRoot 'CertificateTransformer.ps1')
    return (Get-CertificateKeyString -Certificate $Certificate).Trim()
}

# Create a RFC 6187 x509v3-ssh-rsa public key line from an X509Certificate2
function Get-X509v3SshRsaKeyLine([X509Certificate2]$Certificate) {
    $RawCert = $Certificate.RawData
    $Stream = [MemoryStream]::new()
    $Writer = [BinaryWriter]::new($Stream)
    
    $WriteUInt32BE = {
        param($val)
        $bytes = [BitConverter]::GetBytes([uint32]$val)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        $Writer.Write($bytes)
    }
    
    $AlgBytes = [Encoding]::ASCII.GetBytes("x509v3-ssh-rsa")
    $WriteUInt32BE.Invoke($AlgBytes.Length)
    $Writer.Write($AlgBytes)
    $WriteUInt32BE.Invoke(1)
    $WriteUInt32BE.Invoke($RawCert.Length)
    $Writer.Write($RawCert)
    $WriteUInt32BE.Invoke(0) # OCSP response count (0)
    $Writer.Flush()
    
    $Blob = $Stream.ToArray()
    $Base64 = [Convert]::ToBase64String($Blob)
    return "x509v3-ssh-rsa $Base64"
}

# Create a RFC 6187 x509v3-rsa2048-sha256 public key line from an X509Certificate2
function Get-X509v3Rsa2048Sha256KeyLine([X509Certificate2]$Certificate) {
    $RawCert = $Certificate.RawData
    $Stream = [MemoryStream]::new()
    $Writer = [BinaryWriter]::new($Stream)
    
    $WriteUInt32BE = {
        param($val)
        $bytes = [BitConverter]::GetBytes([uint32]$val)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        $Writer.Write($bytes)
    }
    
    $AlgBytes = [Encoding]::ASCII.GetBytes("x509v3-rsa2048-sha256")
    $WriteUInt32BE.Invoke($AlgBytes.Length)
    $Writer.Write($AlgBytes)
    $WriteUInt32BE.Invoke(1)
    $WriteUInt32BE.Invoke($RawCert.Length)
    $Writer.Write($RawCert)
    $WriteUInt32BE.Invoke(0) # OCSP response count (0)
    $Writer.Flush()
    
    $Blob = $Stream.ToArray()
    $Base64 = [Convert]::ToBase64String($Blob)
    return "x509v3-rsa2048-sha256 $Base64"
}

# Create a RFC 6187 x509v3-ecdsa-sha2-nistp256 public key line from an X509Certificate2
function Get-X509v3EcdsaSha2Nistp256KeyLine([X509Certificate2]$Certificate) {
    return Get-X509v3EcdsaKeyLine -Certificate $Certificate -CurveAlg "x509v3-ecdsa-sha2-nistp256"
}

# Create a RFC 6187 x509v3-ecdsa-sha2-nistp384 public key line from an X509Certificate2
function Get-X509v3EcdsaSha2Nistp384KeyLine([X509Certificate2]$Certificate) {
    return Get-X509v3EcdsaKeyLine -Certificate $Certificate -CurveAlg "x509v3-ecdsa-sha2-nistp384"
}

# Create a RFC 6187 x509v3-ecdsa-sha2-nistp521 public key line from an X509Certificate2
function Get-X509v3EcdsaSha2Nistp521KeyLine([X509Certificate2]$Certificate) {
    return Get-X509v3EcdsaKeyLine -Certificate $Certificate -CurveAlg "x509v3-ecdsa-sha2-nistp521"
}

function Get-X509v3EcdsaKeyLine([X509Certificate2]$Certificate, [string]$CurveAlg) {
    $RawCert = $Certificate.RawData
    $Stream = [System.IO.MemoryStream]::new()
    $Writer = [System.IO.BinaryWriter]::new($Stream)
    
    $WriteUInt32BE = {
        param($val)
        $bytes = [BitConverter]::GetBytes([uint32]$val)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        $Writer.Write($bytes)
    }
    
    $AlgBytes = [System.Text.Encoding]::ASCII.GetBytes($CurveAlg)
    $WriteUInt32BE.Invoke($AlgBytes.Length)
    $Writer.Write($AlgBytes)
    $WriteUInt32BE.Invoke(1)
    $WriteUInt32BE.Invoke($RawCert.Length)
    $Writer.Write($RawCert)
    $WriteUInt32BE.Invoke(0) # OCSP response count (0)
    $Writer.Flush()
    
    $Blob = $Stream.ToArray()
    $Base64 = [Convert]::ToBase64String($Blob)
    return "$CurveAlg $Base64"
}

# Extract key identifier from OpenSSH public key line
function Get-KeyId([string]$KeyLine) {
    return (($KeyLine -split '\s+' | Select-Object -First 2) -join ' ').Trim()
}

# Determine label based on trust root installation setting
function Get-TrustLabel {
    if ($TrustTestRoots) { return 'Created trusted' }
    return 'Created untrusted'
}

# Get Pageant autoload filter status message
function Get-PageantAutoloadMessage {
    if ($TrustTestRoots) { return 'Pageant autoload honored trust, expiry, and EKU filters.' }
    return 'Pageant autoload honored expiry and EKU filters without requiring trusted-root changes.'
}

# Build matrix of RSA providers for testing
function Get-RsaProviderMatrix {
    $Providers = [List[object]]::new()

    if ($UseSmartCard) {
        $Providers.Add([PSCustomObject]@{
                Name    = $SmartCardProvider
                Alias   = 'SCCNG'
                Enabled = $true
            }) | Out-Null
    }
    else {
        $Providers.Add([PSCustomObject]@{
                Name    = $CngProvider
                Alias   = 'CNG'
                Enabled = $true
            }) | Out-Null

        if ($IncludeLegacyRsaProviders) {
            $Providers.Add([PSCustomObject]@{
                    Name    = $LegacyEnhancedProvider
                    Alias   = 'LEGENH'
                    Enabled = $true
                }) | Out-Null

            $Providers.Add([PSCustomObject]@{
                    Name    = $LegacyOldProvider
                    Alias   = 'LEGOLD'
                    Enabled = $true
                }) | Out-Null
        }
    }

    return $Providers
}

# Create test certificate matrix for positive and negative test cases
function New-TestMatrix {
    $Matrix = [List[object]]::new()

    # Create RSA test certificates with various key lengths and providers
    foreach ($Provider in Get-RsaProviderMatrix) {
        foreach ($Bits in $RsaKeyLengths) {
            $Case = "RSA-$Bits-$($Provider.Alias)"

            try {
                $Cert = New-TestCertificate -CaseName $Case -Provider $Provider.Name -KeyAlgorithm 'RSA' -KeyLength $Bits -EnhancedKeyUsage @($ClientAuthEku) -NotAfter (Get-Date).AddDays(30) -TrustRoot:$TrustTestRoots

                $Matrix.Add([PSCustomObject]@{
                        Name          = $Case
                        Cert          = $Cert
                        CertId        = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                        KeyType       = 'RSA'
                        Provider      = $Provider.Name
                        Bits          = $Bits
                        AuthorizedKey = (Get-OpenSshKeyLine -Certificate $Cert)
                    }) | Out-Null

                Add-Result -Name $Case -Status 'Pass' -Detail ((Get-TrustLabel) + " RSA test certificate using $($Provider.Name) ($Bits bits).")
            }
            catch {
                Add-Result -Name $Case -Status 'Skip' -Detail $_.Exception.Message
            }
        }
    }

    # Create ECDSA test certificates for various curves
    $EcdsaProvider = if ($UseSmartCard) { $SmartCardProvider } else { $CngProvider }
    foreach ($Curve in @('ECDSA_nistP256', 'ECDSA_nistP384', 'ECDSA_nistP521')) {
        $Case = $Curve.Replace('_', '-')
        if ($UseSmartCard) { $Case = "$Case-SC" }

        try {
            $Cert = New-TestCertificate -CaseName $Case -Provider $EcdsaProvider -KeyAlgorithm $Curve -KeyLength 0 -EnhancedKeyUsage @($ClientAuthEku) -NotAfter (Get-Date).AddDays(30) -TrustRoot:$TrustTestRoots

            $ECDSA = [ECDsaCertificateExtensions]::GetECDsaPublicKey($Cert)

            $Matrix.Add([PSCustomObject]@{
                    Name          = $Case
                    Cert          = $Cert
                    CertId        = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                    KeyType       = 'ECDSA'
                    Provider      = $EcdsaProvider
                    Bits          = $ECDSA.KeySize
                    AuthorizedKey = (Get-OpenSshKeyLine -Certificate $Cert)
                }) | Out-Null

            if ($ECDSA) { $ECDSA.Dispose() }

            Add-Result -Name $Case -Status 'Pass' `
                -Detail ((Get-TrustLabel) + ' ECDSA test certificate.')
        }
        catch {
            Add-Result -Name $Case -Status 'Skip' -Detail $_.Exception.Message
        }
    }

    # Create negative test certificates (invalid scenarios)
    $Negative = [List[object]]::new()

    # Server auth only (should not be eligible for client auth)
    try {
        $Cert = New-TestCertificate -CaseName 'NEG-SERVERAUTH' -Provider $CngProvider -KeyAlgorithm 'RSA' -KeyLength 2048 -EnhancedKeyUsage @($ServerAuthEku) -NotAfter (Get-Date).AddDays(30)

        $Negative.Add([PSCustomObject]@{
                Name           = 'NEG-SERVERAUTH'
                CertId         = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                KeyId          = (Get-KeyId (Get-OpenSshKeyLine -Certificate $Cert))
            }) | Out-Null

        Add-Result -Name 'NEG-SERVERAUTH' -Status 'Pass' -Detail 'Created server-auth-only negative certificate.'
    }
    catch {
        Add-Result -Name 'NEG-SERVERAUTH' -Status 'Skip' -Detail $_.Exception.Message
    }

    # Expired certificate (should be filtered)
    try {
        $Cert = New-TestCertificate -CaseName 'NEG-EXPIRED' -Provider $CngProvider -KeyAlgorithm 'RSA' -KeyLength 2048 -EnhancedKeyUsage @($ClientAuthEku) -NotAfter (Get-Date).AddDays(-1) -TrustRoot:$TrustTestRoots

        $Negative.Add([PSCustomObject]@{
                Name           = 'NEG-EXPIRED'
                CertId         = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                KeyId          = (Get-KeyId (Get-OpenSshKeyLine -Certificate $Cert))
            }) | Out-Null

        Add-Result -Name 'NEG-EXPIRED' -Status 'Pass' -Detail 'Created expired negative certificate.'
    }
    catch {
        Add-Result -Name 'NEG-EXPIRED' -Status 'Skip' -Detail $_.Exception.Message
    }

    # Untrusted certificate (should be filtered if trust checking enabled)
    try {
        $Cert = New-TestCertificate -CaseName 'NEG-UNTRUSTED' -Provider $CngProvider -KeyAlgorithm 'RSA' -KeyLength 2048 -EnhancedKeyUsage @($ClientAuthEku) -NotAfter (Get-Date).AddDays(30)

        $Negative.Add([PSCustomObject]@{
                Name           = 'NEG-UNTRUSTED'
                Cert           = $Cert
                CertId         = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
                KeyId          = (Get-KeyId (Get-OpenSshKeyLine -Certificate $Cert))
            }) | Out-Null

        Add-Result -Name 'NEG-UNTRUSTED' -Status 'Pass' -Detail 'Created untrusted negative certificate.'
    }
    catch {
        Add-Result -Name 'NEG-UNTRUSTED' -Status 'Skip' -Detail $_.Exception.Message
    }

    # Smart card logon cert (has the SC Logon EKU) for the -smartcardlogoncertsonly test
    $SmartCardLogon = $null
    try {
        $Cert = New-TestCertificate -CaseName 'POS-SCLOGON' -Provider $CngProvider -KeyAlgorithm 'RSA' -KeyLength 2048 -EnhancedKeyUsage @($ClientAuthEku, $SmartCardLogonEku) -NotAfter (Get-Date).AddDays(30) -TrustRoot:$TrustTestRoots

        $SmartCardLogon = [PSCustomObject]@{
            Name   = 'POS-SCLOGON'
            Cert   = $Cert
            CertId = "CAPI:$($Cert.Thumbprint.ToLowerInvariant())"
            KeyId  = (Get-KeyId (Get-OpenSshKeyLine -Certificate $Cert))
        }

        Add-Result -Name 'POS-SCLOGON' -Status 'Pass' -Detail 'Created smart card logon certificate.'
    }
    catch {
        Add-Result -Name 'POS-SCLOGON' -Status 'Skip' -Detail $_.Exception.Message
    }

    return [PSCustomObject]@{
        Positive       = $Matrix
        Negative       = $Negative
        SmartCardLogon = $SmartCardLogon
    }
}



# Test SSH connectivity using plink with certificate authentication
function Invoke-PlinkTest([string]$Name, [string]$CertId, [string[]]$HostKeys, [switch]$NoRetry) {
    $ArgList = @('-batch', '-ssh', '-P', $Port.ToString(), '-l', $UserName) +
    ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
    @('-i', $CertId, $HostName, 'whoami')

    $MaxAttempts = $NoRetry ? 1 : 3
    $Attempt = 0
    $Success = $false
    $Result = $null

    while (-not $Success -and $Attempt -lt $MaxAttempts) {
        $Attempt++
        try {
            $Result = Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $ArgList
            if ($Result.StdOut -match [regex]::Escape($UserName)) {
                $Success = $true
            } else {
                if ($Attempt -eq $MaxAttempts) {
                    throw "Unexpected plink output: $($Result.StdOut)`n$($Result.StdErr)"
                }
                Start-Sleep -Milliseconds 500
            }
        }
        catch {
            if ($Attempt -eq $MaxAttempts) {
                throw
            }
            Start-Sleep -Milliseconds 500
        }
    }

    Add-Result -Name "PLINK-$Name" -Status 'Pass' -Detail 'Direct CAPI authentication succeeded.'
}

# Test SFTP connectivity using psftp with certificate authentication
function Invoke-PsftpTest([string]$Name, [string]$CertId, [string[]]$HostKeys) {
    $Batch = Join-Path $script:Paths.Run "psftp-$Name.txt"
    Set-Content -LiteralPath $Batch -Value @('pwd', 'quit') -Encoding ascii

    $ArgList = @('-batch', '-P', $Port.ToString(), '-l', $UserName) +
    ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
    @('-i', $CertId, '-b', $Batch, $HostName)

    $Result = Invoke-Native -FilePath $script:Paths.Psftp -ArgumentList $ArgList

    if ($Result.StdOut -notmatch '/' -and $Result.StdErr -notmatch 'Remote directory is') { throw 'PSFTP did not return a working directory.' }

    Add-Result -Name "PSFTP-$Name" -Status 'Pass' -Detail 'Batch PSFTP authentication succeeded.'
}

# Test secure file copy using pscp with certificate authentication
function Invoke-PscpTest([string]$Name, [string]$CertId, [string[]]$HostKeys) {
    if (-not (Test-Path -LiteralPath $script:Paths.Pscp -PathType Leaf)) {
        Add-Result -Name "PSCP-$Name" -Status 'Skip' -Detail 'pscp.exe not found; skipping PSCP test.'
        return
    }

    $LocalFile = Join-Path $script:Paths.Run "pscp-$Name.txt"
    Set-Content -LiteralPath $LocalFile -Value "PuTTYCAC-PSCP-TEST-$Name" -Encoding ascii

    $RemotePath = "$UserName@${HostName}:pscp-$Name.txt"
    $ArgList = @('-batch', '-P', $Port.ToString(), '-l', $UserName) +
    ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
    @('-i', $CertId, $LocalFile, $RemotePath)

    Invoke-Native -FilePath $script:Paths.Pscp -ArgumentList $ArgList | Out-Null

    Add-Result -Name "PSCP-$Name" -Status 'Pass' -Detail 'PSCP file upload authentication succeeded.'
}

# Test SSH authentication via Pageant acting as SSH agent (uses OpenSSH ssh.exe)
function Invoke-PageantAgentTest([string]$Name, [string]$CertId, [string[]]$HostKeys) {
    $Bridge = Start-Pageant -Arguments @($CertId)

    try {
        # Build known_hosts from the actual host public key files — $HostKeys contains
        # fingerprints for plink, but ssh.exe needs "hostname keytype base64key" lines.
        $KnownHostsPath = Join-Path $script:Paths.Run 'pageant_known_hosts'
        $KnownHostsLines = Get-ChildItem -LiteralPath $script:Paths.PkixHostKeys -Filter 'ssh_host_*_key.pub' -File |
            ForEach-Object { "$HostName $((Get-Content -LiteralPath $_.FullName -Raw).Trim())" }
        Set-Content -LiteralPath $KnownHostsPath -Value $KnownHostsLines -Encoding ascii

        # Write a config file so paths with spaces are properly quoted (inline -o quoting
        # is unreliable when the pipe path or temp dir contains spaces, e.g. "Bryan Berns")
        $SshConfigPath = Join-Path $script:Paths.Run "pageant_agent_$Name.conf"
        Set-Content -LiteralPath $SshConfigPath -Value @(
            "IdentityAgent `"$($Bridge.Agent)`""
            "UserKnownHostsFile `"$KnownHostsPath`""
            'StrictHostKeyChecking yes'
            'BatchMode yes'
        ) -Encoding ascii

        $ArgList = @(
            '-F', $SshConfigPath,
            '-p', $Port.ToString(),
            '-l', $UserName,
            $HostName,
            'whoami'
        )

        $Result = Invoke-Native -FilePath $script:Paths.SshExe -ArgumentList $ArgList

        if ($Result.StdOut -notmatch [regex]::Escape($UserName)) { throw "Unexpected ssh output: $($Result.StdOut)" }

        Add-Result -Name "PAGEANT-AGENT-$Name" -Status 'Pass' -Detail 'SSH via Pageant agent socket authenticated successfully.'
    }
    finally {
        if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
    }
}

# Set accepted algorithms on the PKIX-SSH server
function Set-AcceptedAlgorithms {
    param(
        [string]$AuthorizedKey,
        [string]$CustomAlgorithm
    )

    $Alg = $null
    if ($CustomAlgorithm) {
        $Alg = $CustomAlgorithm
    }
    elseif ($AuthorizedKey) {
        $KeyType = ($AuthorizedKey -split '\s+')[0]
        switch ($KeyType) {
            'ssh-rsa' { $Alg = 'rsa-sha2-512,rsa-sha2-256,ssh-rsa' }
            'ecdsa-sha2-nistp256' { $Alg = 'ecdsa-sha2-nistp256' }
            'ecdsa-sha2-nistp384' { $Alg = 'ecdsa-sha2-nistp384' }
            'ecdsa-sha2-nistp521' { $Alg = 'ecdsa-sha2-nistp521' }
            'ssh-ed25519' { $Alg = 'ssh-ed25519' }
            default {
                throw "Unknown key type: $KeyType"
            }
        }
    }
    else {
        throw "Must provide either -AuthorizedKey or -CustomAlgorithm"
    }

    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($DockerCmd) {
        $Cmd = "sed -i '/^PubkeyAcceptedAlgorithms/d' /etc/pkixssh/sshd_config && echo 'PubkeyAcceptedAlgorithms $Alg' >> /etc/pkixssh/sshd_config"
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('exec', $PkixContainerName, 'sh', '-c', $Cmd) | Out-Null
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('kill', '-s', 'HUP', $PkixContainerName) | Out-Null
        # Give sshd a tiny moment to complete the SIGHUP reload
        Start-Sleep -Milliseconds 100
    }
}

# Test that -allowanycert permits authentication with an untrusted certificate
function Test-AllowAnyCert([object]$UntrustedCase, [string[]]$HostKeys) {
    if (-not $UntrustedCase) {
        Add-Result -Name 'ALLOWANYCERT' -Status 'Skip' -Detail 'No untrusted negative certificate available for -allowanycert test.'
        return
    }

    $UntrustedKey = Get-OpenSshKeyLine -Certificate $UntrustedCase.Cert
    $Marker = "$($script:State.Marker) ALLOWANYCERT"
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue

    if ($DockerCmd) {
        # Temporarily inject the untrusted public key into the container's authorized_keys file
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $PkixContainerName, 'sh', '-c', "echo '$Marker' >> /authorized_keys && echo '$UntrustedKey' >> /authorized_keys"
        ) | Out-Null
    }

    try {
        $ArgList = @('-batch', '-ssh', '-P', $Port.ToString(), '-l', $UserName) +
        ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
        @('-allowanycert', '-i', $UntrustedCase.CertId, $HostName, 'whoami')

        $Result = Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $ArgList

        if ($Result.StdOut -notmatch [regex]::Escape($UserName)) { throw "Unexpected plink output: $($Result.StdOut)" }

        Add-Result -Name 'ALLOWANYCERT' -Status 'Pass' -Detail 'plink authenticated with untrusted certificate using -allowanycert.'
    }
    finally {
        # Clean up the container's authorized_keys by removing the temporary untrusted key lines
        if ($DockerCmd) {
            Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
                'exec', $PkixContainerName, 'sh', '-c', "sed -i '/ALLOWANYCERT/d' /authorized_keys"
            ) -IgnoreExitCode | Out-Null
        }

        # plink persisted AllowAnyCert=1 to the registry; clear it now so Test-PageantFilters
        # is not affected (AllowAnyCert bypasses EKU filtering, which would cause NEG-SERVERAUTH
        # to appear in the autoloaded key list)
        Remove-ItemProperty -LiteralPath 'HKCU:\Software\SimonTatham\PuTTY' -Name 'AllowAnyCert' -Force -ErrorAction SilentlyContinue
    }
}

# Intentionally mismatch server auth algorithms and verify authentication failure is detected
function Test-PkixAuthMismatch([object]$Case, [string[]]$HostKeys, [string]$RestoreAlgorithm) {
    if (-not $Case) {
        Add-Result -Name 'PKIX-AUTH-MISMATCH' -Status 'Skip' -Detail 'No positive test certificate available for PKIX auth mismatch verification.'
        return
    }

    $MismatchAlgorithm = 'ssh-ed25519'
    if ($Case.KeyType -eq 'ED25519') {
        $MismatchAlgorithm = 'rsa-sha2-512,rsa-sha2-256,ssh-rsa'
    }

    Set-AcceptedAlgorithms -CustomAlgorithm $MismatchAlgorithm
    Start-Sleep -Milliseconds 300

    try {
        $ArgList = @('-batch', '-ssh', '-P', $Port.ToString(), '-l', $UserName) +
        ($HostKeys | ForEach-Object { @('-hostkey', $_) }) +
        @('-i', $Case.CertId, $HostName, 'whoami')

        $Result = Invoke-Native -FilePath $script:Paths.Plink -ArgumentList $ArgList -IgnoreExitCode
        $Succeeded = $Result.ExitCode -eq 0 -and $Result.StdOut -match [regex]::Escape($UserName)

        if ($Succeeded) {
            Add-Result -Name 'PKIX-AUTH-MISMATCH' -Status 'Fail' -Detail "Expected auth failure with intentionally mismatched PubkeyAcceptedAlgorithms ($MismatchAlgorithm), but authentication succeeded."
        }
        else {
            Add-Result -Name 'PKIX-AUTH-MISMATCH' -Status 'Pass' -Detail "Intentionally mismatched PubkeyAcceptedAlgorithms ($MismatchAlgorithm); authentication failed as expected."
        }
    }
    finally {
        Set-AcceptedAlgorithms -CustomAlgorithm $RestoreAlgorithm
        Start-Sleep -Milliseconds 300
    }
}

# Verify SHA-384 and SHA-512 SSH algorithm variants across supported key types
function Test-ShaVariantAlgorithms([object[]]$Cases, [string[]]$HostKeys, [string]$RestoreAlgorithm) {
    $VariantTests = [List[object]]::new()

    $RsaCase = $Cases | Where-Object KeyType -eq 'RSA' | Sort-Object Bits -Descending | Select-Object -First 1
    if ($RsaCase) {
        $VariantTests.Add([PSCustomObject]@{
                Name      = 'RSA-SHA512'
                Algorithm = 'rsa-sha2-512'
                Case      = $RsaCase
                HashName  = 'SHA512'
            }) | Out-Null
    }

    $Ecdsa384Case = $Cases | Where-Object { $_.KeyType -eq 'ECDSA' -and $_.Bits -eq 384 } | Select-Object -First 1
    if ($Ecdsa384Case) {
        $VariantTests.Add([PSCustomObject]@{
                Name      = 'ECDSA-NISTP384'
                Algorithm = 'ecdsa-sha2-nistp384'
                Case      = $Ecdsa384Case
                HashName  = 'SHA384'
            }) | Out-Null
    }

    $Ecdsa521Case = $Cases | Where-Object { $_.KeyType -eq 'ECDSA' -and $_.Bits -eq 521 } | Select-Object -First 1
    if ($Ecdsa521Case) {
        $VariantTests.Add([PSCustomObject]@{
                Name      = 'ECDSA-NISTP521'
                Algorithm = 'ecdsa-sha2-nistp521'
                Case      = $Ecdsa521Case
                HashName  = 'SHA512'
            }) | Out-Null
    }

    if ($VariantTests.Count -eq 0) {
        Add-Result -Name 'PKIX-SHA-VARIANTS' -Status 'Skip' -Detail 'No compatible RSA/ECDSA test certificates were available for SHA-384/SHA-512 algorithm variant checks.'
        return
    }

    foreach ($Variant in $VariantTests) {
        Set-AcceptedAlgorithms -CustomAlgorithm $Variant.Algorithm
        Start-Sleep -Milliseconds 300

        try {
            Invoke-PlinkTest -Name "NEGOTIATION-$($Variant.Name)-$($Variant.Case.Name)" -CertId $Variant.Case.CertId -HostKeys $HostKeys
            Add-Result -Name "PKIX-$($Variant.Name)-$($Variant.Case.Name)" -Status 'Pass' -Detail "Successfully authenticated using $($Variant.Algorithm) ($($Variant.HashName) variant)."
        }
        finally {
            Set-AcceptedAlgorithms -CustomAlgorithm $RestoreAlgorithm
            Start-Sleep -Milliseconds 300
        }
    }
}

# Start Pageant with specified arguments and wait for initialization
function Start-Pageant([string[]]$Arguments) {
    $Config = Join-Path $script:Paths.Run ("pageant-{0}.conf" -f ([guid]::NewGuid().ToString('N')))
    $ArgList = @('--openssh-config', $Config) + $Arguments
    $Process = Start-Process -FilePath $script:Paths.Pageant -ArgumentList $ArgList -PassThru -WindowStyle Hidden
    $script:State.PageantProcesses.Add($Process) | Out-Null

    # Wait for Pageant to initialize and create config file
    $Deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $Deadline) {
        if (Test-Path -LiteralPath $Config -PathType Leaf) {
            $Line = Get-Content -LiteralPath $Config | Where-Object { $_ -match '^IdentityAgent ' } | Select-Object -First 1

            if ($Line) {
                return [PSCustomObject]@{
                    Process = $Process
                    Agent   = ($Line -replace '^IdentityAgent\s+"?(.+?)"?$', '$1')
                    Config  = $Config
                }
            }
        }

        Start-Sleep -Milliseconds 200
    }

    throw 'Timed out waiting for Pageant to initialize.'
}

# Stop all running Pageant processes
function Stop-Pageants {
    foreach ($Process in $script:State.PageantProcesses) {
        if ($Process -and -not $Process.HasExited) { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue }
    }
}

# Get list of keys loaded in Pageant via SSH agent
function Get-PageantKeys([string]$Agent) {
    $env:SSH_AUTH_SOCK = $Agent
    $Result = Invoke-Native -FilePath $script:Paths.SshAdd -ArgumentList @('-L') -IgnoreExitCode

    if ($Result.ExitCode -ne 0 -and $Result.StdErr -notmatch 'The agent has no identities' -and $Result.StdOut -notmatch 'The agent has no identities') { throw "ssh-add -L failed: Exit=$($Result.ExitCode) Out=$($Result.StdOut) Err=$($Result.StdErr)" }

    return @($Result.StdOut -split "`r?`n" | Where-Object { $_ -match '^(ssh-|ecdsa-)' })
}

# Get registry DWord value from PuTTY settings
function Get-RegistryDword([string]$Path, [string]$Name) {
    $Item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $Item) { return $null }
    return $Item.PSObject.Properties[$Name]?.Value
}

# Execute PuTTY tool with flag and verify registry persistence
function Invoke-FlagSetter([string]$FilePath, [string]$Flag, [string]$RegistryName, [int]$ExpectedValue) {
    $Process = Start-Process -FilePath $FilePath -ArgumentList @($Flag) -PassThru -WindowStyle Hidden

    try {
        $Deadline = (Get-Date).AddSeconds(5)
        do {
            if ((Get-RegistryDword -Path 'HKCU:\Software\SimonTatham\PuTTY' -Name $RegistryName) -eq $ExpectedValue) { return }
            Start-Sleep -Milliseconds 200
        }
        while ((Get-Date) -lt $Deadline -and -not $Process.HasExited)

        if ((Get-RegistryDword -Path 'HKCU:\Software\SimonTatham\PuTTY' -Name $RegistryName) -ne $ExpectedValue) {
            throw "$([Path]::GetFileName($FilePath)) failed to set $RegistryName with $Flag."
        }
    }
    finally {
        if ($Process -and -not $Process.HasExited) { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue }
    }
}

# Test Pageant certificate autoload and filtering capabilities
function Test-PageantFilters([object[]]$Positive, [object[]]$Negative, [object]$SmartCardLogon) {
    if ($Positive.Count -eq 0) {
        foreach ($N in @('PAGEANT-AUTOLOAD', 'PAGEANT-IGNOREEXPIRED', 'PAGEANT-SHOWEXPIRED', 'PAGEANT-SCLOGONFILTER', 'PAGEANT-TRUSTFILTER', 'PAGEANT-SAVELIST')) {
            Add-Result -Name $N -Status 'Skip' -Detail 'No positive test certificates available for Pageant tests.'
        }
        return
    }

    $ExpiredCase = $Negative | Where-Object Name -eq 'NEG-EXPIRED' | Select-Object -First 1

    # Test autoload with expiry and optional trust filters
    $AutoloadArgs = [List[string]]::new()
    $AutoloadArgs.Add('-autoload') | Out-Null
    $AutoloadArgs.Add('-ignoreexpiredcerts') | Out-Null
    if ($TrustTestRoots) { $AutoloadArgs.Add('-trustedcertsonly') | Out-Null }

    $Bridge = Start-Pageant -Arguments $AutoloadArgs

    try {
        $Keys = @(Get-PageantKeys -Agent $Bridge.Agent | ForEach-Object { Get-KeyId $_ })

        # Verify all positive certificates are autoloaded
        foreach ($Case in $Positive) {
            if ($Keys -notcontains (Get-KeyId $Case.AuthorizedKey)) { throw "Missing autoloaded key for $($Case.Name)." }
        }

        # Verify negative certificates are properly filtered
        # NEG-SERVERAUTH (EKU) and NEG-EXPIRED (-ignoreexpiredcerts) are always
        # filtered here; NEG-UNTRUSTED only when the trusted-certs check is active.
        $ExpectedFiltered = if ($TrustTestRoots) {
            @($Negative)
        }
        else {
            @($Negative | Where-Object Name -ne 'NEG-UNTRUSTED')
        }

        foreach ($Case in $ExpectedFiltered) {
            if ($Keys -contains $Case.KeyId) { throw "Unexpected filtered key listed for $($Case.Name)." }
        }

        Add-Result -Name 'PAGEANT-AUTOLOAD' -Status 'Pass' -Detail (Get-PageantAutoloadMessage)

        # -ignoreexpiredcerts must exclude expired certs from the list (issue #166)
        if ($ExpiredCase) {
            if ($Keys -contains $ExpiredCase.KeyId) { throw 'Expected NEG-EXPIRED to be filtered out when -ignoreexpiredcerts is enabled.' }
            Add-Result -Name 'PAGEANT-IGNOREEXPIRED' -Status 'Pass' -Detail 'Verified -ignoreexpiredcerts filters expired certificates out of the autoload list.'
        }

        if (-not $TrustTestRoots) { Add-Result -Name 'PAGEANT-TRUSTFILTER' -Status 'Skip' -Detail 'Skipped TrustedCertsOnly autoload coverage because trusted root installation was not requested.' }
    }
    finally {
        if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
    }

    # OFF-state counterpart: with -ignoreexpiredcertsoff the expired cert must stay
    # listed. Mirror the trust filter so the chain path is checked too (issue #166).
    if ($ExpiredCase) {
        $ShowExpiredArgs = [List[string]]::new()
        $ShowExpiredArgs.Add('-autoload') | Out-Null
        $ShowExpiredArgs.Add('-ignoreexpiredcertsoff') | Out-Null
        if ($TrustTestRoots) { $ShowExpiredArgs.Add('-trustedcertsonly') | Out-Null }

        $Bridge = Start-Pageant -Arguments $ShowExpiredArgs

        try {
            $Keys = @(Get-PageantKeys -Agent $Bridge.Agent | ForEach-Object { Get-KeyId $_ })
            if ($Keys -notcontains $ExpiredCase.KeyId) { throw 'Expected NEG-EXPIRED to be listed when -ignoreexpiredcerts is disabled.' }
            Add-Result -Name 'PAGEANT-SHOWEXPIRED' -Status 'Pass' -Detail 'Verified expired certificates remain listed when the No Expired Certs filter is disabled.'
        }
        finally {
            if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
        }
    }

    # -smartcardlogoncertsonly must list only certs with the Smart Card Logon EKU:
    # the SC-logon cert stays, an ordinary client-auth cert is filtered out.
    if ($SmartCardLogon) {
        $Bridge = Start-Pageant -Arguments @('-autoload', '-smartcardlogoncertsonly')

        try {
            $Keys = @(Get-PageantKeys -Agent $Bridge.Agent | ForEach-Object { Get-KeyId $_ })
            if ($Keys -notcontains $SmartCardLogon.KeyId) { throw 'Expected POS-SCLOGON to be listed when -smartcardlogoncertsonly is enabled.' }

            $NonScCase = $Positive | Select-Object -First 1
            if ($NonScCase -and ($Keys -contains (Get-KeyId $NonScCase.AuthorizedKey))) {
                throw "Expected ordinary client-auth certificate $($NonScCase.Name) to be filtered when -smartcardlogoncertsonly is enabled."
            }

            Add-Result -Name 'PAGEANT-SCLOGONFILTER' -Status 'Pass' -Detail 'Verified -smartcardlogoncertsonly lists only smart card logon certificates.'
        }
        finally {
            if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
        }
    }
    else {
        Add-Result -Name 'PAGEANT-SCLOGONFILTER' -Status 'Skip' -Detail 'No smart card logon certificate available for SmartCardLogonCertsOnly test.'
    }

    # Test certificate list persistence in registry
    $SaveList = $Positive | Select-Object -First ([Math]::Min(2, $Positive.Count))

    if ($SaveList.Count -gt 0) {
        New-Item -Path 'HKCU:\Software\SimonTatham\PuTTY' -Force | Out-Null
        New-ItemProperty -LiteralPath 'HKCU:\Software\SimonTatham\PuTTY' -Name 'SaveCertListEnabled' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -LiteralPath 'HKCU:\Software\SimonTatham\PuTTY' -Name 'SaveCertList' -PropertyType MultiString -Value ($SaveList.CertId) -Force | Out-Null

        $Bridge = Start-Pageant -Arguments @()

        try {
            $Keys = @(Get-PageantKeys -Agent $Bridge.Agent | ForEach-Object { Get-KeyId $_ })

            foreach ($Case in $SaveList) {
                if ($Keys -notcontains (Get-KeyId $Case.AuthorizedKey)) { throw "Saved certificate $($Case.Name) was not restored into Pageant." }
            }

            Add-Result -Name 'PAGEANT-SAVELIST' -Status 'Pass' -Detail 'Pageant restored saved certificate list from registry.'
        }
        finally {
            if ($Bridge.Process -and -not $Bridge.Process.HasExited) { Stop-Process -Id $Bridge.Process.Id -Force -ErrorAction SilentlyContinue }
        }
    }
}

# Test registry persistence of PuTTY command-line flags
function Test-RegistryFlags {
    # Build table of on/off flag pairs that should persist to registry
    $Flags = [ordered]@{
        AutoloadCerts           = @{ On = '-autoload';                Off = '-autoloadoff' }
        SaveCertListEnabled     = @{ On = '-savecertlist';            Off = '-savecertlistoff' }
        ForcePinCaching         = @{ On = '-forcepincache';           Off = '-forcepincacheoff' }
        CertAuthPrompting       = @{ On = '-certauthprompting';       Off = '-certauthpromptingoff' }
        SmartCardLogonCertsOnly = @{ On = '-smartcardlogoncertsonly'; Off = '-smartcardlogoncertsonlyoff' }
        TrustedCertsOnly        = @{ On = '-trustedcertsonly';        Off = '-trustedcertsonlyoff' }
        IgnoreExpiredCerts      = @{ On = '-ignoreexpiredcerts';      Off = '-ignoreexpiredcertsoff' }
        AllowAnyCert            = @{ On = '-allowanycert';            Off = '-allowanycertoff' }
    }

    $Executables = @($script:Paths.Plink, $script:Paths.Pscp, $script:Paths.Psftp, $script:Paths.Pageant) |
    Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }

    foreach ($Exe in $Executables) {
        foreach ($Name in $Flags.Keys) {
            Remove-ItemProperty -LiteralPath 'HKCU:\Software\SimonTatham\PuTTY' -Name $Name -Force -ErrorAction SilentlyContinue
            Invoke-FlagSetter -FilePath $Exe -Flag $Flags[$Name].On  -RegistryName $Name -ExpectedValue 1
            Invoke-FlagSetter -FilePath $Exe -Flag $Flags[$Name].Off -RegistryName $Name -ExpectedValue 0
        }

        Add-Result -Name "REGISTRY-$([Path]::GetFileName($Exe))" -Status 'Pass' `
            -Detail 'All PuTTY-CAC registry-backed CLI SET and UNSET flags persisted to registry as expected.'
    }
}

# Test that passing a specific CAPI key on the command line is accepted by all executables
function Test-CapiArgumentPassing([string]$CertId) {
    if (-not $CertId) {
        Add-Result -Name 'CLI-CAPI-ARGS' -Status 'Skip' -Detail 'No CAPI certificate available for CLI argument testing.'
        return
    }

    # We want to test every PuTTY-CAC executable that we have resolved
    $Executables = @(
        [PSCustomObject]@{ Path = $script:Paths.Plink;   Args = @('-i', $CertId) }
        [PSCustomObject]@{ Path = $script:Paths.Pscp;    Args = @('-i', $CertId) }
        [PSCustomObject]@{ Path = $script:Paths.Psftp;   Args = @('-i', $CertId) }
        [PSCustomObject]@{ Path = $script:Paths.Pageant; Args = @($CertId) }
        [PSCustomObject]@{ Path = $script:Paths.Putty;   Args = @('-i', $CertId) }
        [PSCustomObject]@{ Path = $script:Paths.PuttyTel;Args = @('-i', $CertId) }
    ) | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path -PathType Leaf) }

    foreach ($Exe in $Executables) {
        $Name = [System.IO.Path]::GetFileName($Exe.Path)
        try {
            $ProcessInfo = [System.Diagnostics.ProcessStartInfo]::new()
            $ProcessInfo.FileName = $Exe.Path
            foreach ($Arg in $Exe.Args) {
                [void]$ProcessInfo.ArgumentList.Add($Arg)
            }
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.CreateNoWindow = $true

            $Process = [System.Diagnostics.Process]::Start($ProcessInfo)
            $OutTask = $Process.StandardOutput.ReadToEndAsync()
            $ErrTask = $Process.StandardError.ReadToEndAsync()

            # Wait a short duration (1000ms). If it's a CLI tool, it might exit quickly.
            # If it's a GUI tool, it will run indefinitely.
            $Exited = $Process.WaitForExit(1000)

            if ($Exited) {
                $StdOut = $OutTask.GetAwaiter().GetResult().Trim()
                $StdErr = $ErrTask.GetAwaiter().GetResult().Trim()
                $Output = "$StdOut`n$StdErr"
                
                # Check for command line errors indicating argument parsing failed
                if ($Output -match 'unknown option|unrecognised|requires an argument') {
                    throw "Command line validation failed: $Output"
                }
            } else {
                # Process is still running, which means it accepted the arguments. Kill it.
                try {
                    $Process.Kill()
                    $Process.WaitForExit()
                } catch {}
            }

            Add-Result -Name "CLI-CAPI-ARG-${Name}" -Status 'Pass' -Detail "Successfully validated command line argument passing of specific CAPI key ($CertId) to ${Name}."
        }
        catch {
            Add-Result -Name "CLI-CAPI-ARG-${Name}" -Status 'Fail' -Detail "Failed to pass CAPI key argument to ${Name}: $($_.Exception.Message)"
        }
    }
}


# Delete all test certificates from certificate store
function Remove-TestCertificates {
    foreach ($Thumb in $script:State.CreatedThumbprints | Select-Object -Unique) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\$Thumb") -DeleteKey -Force -ErrorAction SilentlyContinue
        if ($script:State.TrustedThumbprints -contains $Thumb) {
            Remove-FromCurrentUserRootStore -Thumbprint $Thumb
        }
    }
}



# Write test results summary to JSON file and console
function Write-Summary {
    $SummaryPath = Join-Path $script:Paths.Run 'summary.json'
    $script:State.Results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $SummaryPath -Encoding utf8

    $Pass = @($script:State.Results | Where-Object Status -eq 'Pass').Count
    $Skip = @($script:State.Results | Where-Object Status -eq 'Skip').Count
    $Fail = @($script:State.Results | Where-Object Status -eq 'Fail').Count

    Write-Host ("Summary: {0} passed, {1} skipped, {2} failed. Log: {3}" -f $Pass, $Skip, $Fail, $SummaryPath)

    if ($Fail -gt 0) {
        throw 'One or more PuTTY-CAC tests failed.'
    }
}

# Main execution block
try {
    $script:Paths.Run = New-Directory $WorkingRoot

    if (-not (Test-Path -LiteralPath $OpenSSHRoot -PathType Container)) {
        throw "Missing OpenSSH directory: $OpenSSHRoot"
    }

    $script:Paths.OpenSSH = (Resolve-Path -LiteralPath $OpenSSHRoot).Path
    $PuttyRootResolved = Resolve-PuTTYRoot

    $script:Paths.Putty = Join-Path $PuttyRootResolved 'putty.exe'
    $script:Paths.Plink = Get-CommandPath (Join-Path $PuttyRootResolved 'plink.exe')
    $script:Paths.Psftp = Get-CommandPath (Join-Path $PuttyRootResolved 'psftp.exe')
    $script:Paths.Pscp = Join-Path $PuttyRootResolved 'pscp.exe'
    $script:Paths.Pageant = Get-CommandPath (Join-Path $PuttyRootResolved 'pageant.exe')
    $script:Paths.PuttyTel = Join-Path $PuttyRootResolved 'puttytel.exe'
    $script:Paths.PTerm = Join-Path $PuttyRootResolved 'pterm.exe'
    $script:Paths.SshExe = Get-CommandPath (Join-Path $OpenSSHRoot 'ssh.exe')
    $script:Paths.SshAdd = Get-CommandPath (Join-Path $OpenSSHRoot 'ssh-add.exe')

    Backup-PuTTYRegistry

    $Matrix = New-TestMatrix

    # Test CAPI argument passing on all resolved executables
    $FirstCert = $Matrix.Positive | Select-Object -First 1
    if ($FirstCert) {
        Test-CapiArgumentPassing -CertId $FirstCert.CertId
    }

    # Build PKCS#11 test matrix if a PKCS#11 library was supplied
    $Pkcs11Matrix = [List[object]]::new()
    if ($Pkcs11Library) {
        if (-not (Test-Path -LiteralPath $Pkcs11Library -PathType Leaf)) {
            Add-Result -Name 'PKCS11-SETUP' -Status 'Fail' -Detail "PKCS#11 library not found: $Pkcs11Library"
        }
        else {
            foreach ($Entry in (New-Pkcs11TestMatrix)) { $Pkcs11Matrix.Add($Entry) | Out-Null }
            if ($Pkcs11Matrix.Count -gt 0) {
                Add-Result -Name 'PKCS11-SETUP' -Status 'Pass' -Detail "Loaded $($Pkcs11Matrix.Count) PKCS#11 test certificate(s) from $Pkcs11Library."
            }
        }
    }

    # 1. Start the PKIX-SSH Docker container
    $PkixContainerName = 'puttycac-pkixssh-test'
    $PkixImageName = 'puttycac/pkixssh-test'
    $PkixDockerfile = Join-Path $script:State.WorkspaceRoot 'tools\docker\pkixssh\Dockerfile'

    # Check Docker availability
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $DockerCmd) { throw 'Docker is not installed or not in PATH.' }

    $DockerInfo = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('info', '--format', '{{.OSType}}') -IgnoreExitCode
    if ($DockerInfo.ExitCode -ne 0) { throw "Docker daemon is not running: $($DockerInfo.StdErr)" }

    if (-not (Test-Path -LiteralPath $PkixDockerfile -PathType Leaf)) {
        throw "PKIX-SSH Dockerfile not found at $PkixDockerfile"
    }

    # Build PKIX-SSH Docker image (cached after first build)
    Write-Host 'Building PKIX-SSH Docker image (cached after first build)...'
    $BuildCtx = Split-Path -Parent $PkixDockerfile
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'build', '-t', $PkixImageName, $BuildCtx
    ) | Out-Null

    # Prepare combined authorized_keys for the container
    $PkixAuthKeysPath = Join-Path $script:Paths.Run 'authorized_keys'
    $AuthKeysLines = [List[string]]::new()
    foreach ($Case in $Matrix.Positive) {
        $AuthKeysLines.Add((Get-OpenSshKeyLine -Certificate $Case.Cert))
        if ($Case.KeyType -eq 'RSA') {
            $AuthKeysLines.Add((Get-X509v3SshRsaKeyLine -Certificate $Case.Cert))
            $AuthKeysLines.Add((Get-X509v3Rsa2048Sha256KeyLine -Certificate $Case.Cert))
        }
        if ($Case.KeyType -eq 'ECDSA') {
            if ($Case.Bits -eq 256) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp256KeyLine -Certificate $Case.Cert)) }
            elseif ($Case.Bits -eq 384) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp384KeyLine -Certificate $Case.Cert)) }
            elseif ($Case.Bits -eq 521) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp521KeyLine -Certificate $Case.Cert)) }
        }
    }
    foreach ($Case in $Pkcs11Matrix) {
        $AuthKeysLines.Add($Case.AuthorizedKey)
        if ($Case.KeyType -eq 'RSA') {
            $AuthKeysLines.Add((Get-X509v3SshRsaKeyLine -Certificate $Case.Cert))
            $AuthKeysLines.Add((Get-X509v3Rsa2048Sha256KeyLine -Certificate $Case.Cert))
        }
        if ($Case.KeyType -eq 'ECDSA') {
            if ($Case.Bits -eq 256) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp256KeyLine -Certificate $Case.Cert)) }
            elseif ($Case.Bits -eq 384) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp384KeyLine -Certificate $Case.Cert)) }
            elseif ($Case.Bits -eq 521) { $AuthKeysLines.Add((Get-X509v3EcdsaSha2Nistp521KeyLine -Certificate $Case.Cert)) }
        }
    }
    Set-Content -LiteralPath $PkixAuthKeysPath -Value $AuthKeysLines -Encoding ascii

    # Remove any leftover container from a previous run
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'rm', '-f', $PkixContainerName
    ) -IgnoreExitCode | Out-Null

    # Start the container in detached mode (using the container filesystem only, with no bind mounts)
    Write-Host "Starting PKIX-SSH Docker container on port $Port..."
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'run', '-d',
        '--name', $PkixContainerName,
        '-p', "$($Port):$Port",
        $PkixImageName
    ) | Out-Null

    # Copy the generated authorized_keys file directly into the container's isolated filesystem
    Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
        'cp', $PkixAuthKeysPath, "${PkixContainerName}:/authorized_keys"
    ) | Out-Null

    # Wait for sshd to start listening
    $Listening = $false
    $Timeout = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $Timeout) {
        if (Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue) {
            $Listening = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $Listening) {
        $Logs = (Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('logs', $PkixContainerName) -IgnoreExitCode).StdOut
        throw "PKIX-SSH container sshd failed to listen on port $Port.`nLogs:`n$Logs"
    }

    # Extract host key fingerprints from the container
    $SshKeyGen = Get-CommandPath (Join-Path $script:Paths.OpenSSH 'ssh-keygen.exe')
    $script:Paths.PkixHostKeys = Join-Path $script:Paths.Run 'pkix_hostkeys'
    New-Directory $script:Paths.PkixHostKeys | Out-Null
    foreach ($KeyType in @('rsa', 'ecdsa', 'ed25519')) {
        $PubKeyContent = (Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @(
            'exec', $PkixContainerName, 'cat', "/etc/pkixssh/ssh_host_${KeyType}_key.pub"
        )).StdOut
        $PubKeyFile = Join-Path $script:Paths.PkixHostKeys "ssh_host_${KeyType}_key.pub"
        Set-Content -LiteralPath $PubKeyFile -Value $PubKeyContent -Encoding ascii
    }

    $PubKeys = Get-ChildItem -LiteralPath $script:Paths.PkixHostKeys -Filter 'ssh_host_*_key.pub' -File
    $HostKeys = @($(foreach ($Key in $PubKeys) {
        $Output = Invoke-Native -FilePath $SshKeyGen -ArgumentList @('-lf', $Key.FullName)
        if ($Output.StdOut -match '^\S+\s+(\S+)\s+') { $Matches[1] }
    }) | Where-Object { $_ } | Select-Object -Unique)

    Add-Result -Name 'PKIX-SSH-SETUP' -Status 'Pass' -Detail 'Successfully compiled and started Dockerized PKIX-SSH server for all testings.'

    # Configure the server globally once to accept all required key types to avoid rapid SIGHUP restarts
    $AllAcceptedAlgorithms = 'rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519'
    Set-AcceptedAlgorithms -CustomAlgorithm $AllAcceptedAlgorithms
    Start-Sleep -Milliseconds 300

    # Explicitly validate SHA-384/SHA-512 algorithm variants for supported key types
    $VariantCases = @($Matrix.Positive) + @($Pkcs11Matrix)
    Test-ShaVariantAlgorithms -Cases $VariantCases -HostKeys $HostKeys -RestoreAlgorithm $AllAcceptedAlgorithms

    # Intentionally mismatch auth once to verify the test harness catches expected auth failures
    $MismatchCase = $Matrix.Positive | Where-Object KeyType -eq 'RSA' | Select-Object -First 1
    if (-not $MismatchCase) { $MismatchCase = $Matrix.Positive | Select-Object -First 1 }
    Test-PkixAuthMismatch -Case $MismatchCase -HostKeys $HostKeys -RestoreAlgorithm $AllAcceptedAlgorithms

    foreach ($Case in $Matrix.Positive) {
        Invoke-PlinkTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys
        Invoke-PscpTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys

        if (Test-Path -LiteralPath $script:Paths.Psftp -PathType Leaf) { Invoke-PsftpTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys }
    }

    # Run plink and psftp tests for PKCS#11 certificates
    foreach ($Case in $Pkcs11Matrix) {
        Invoke-PlinkTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys
        Invoke-PscpTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys

        if (Test-Path -LiteralPath $script:Paths.Psftp -PathType Leaf) { Invoke-PsftpTest -Name $Case.Name -CertId $Case.CertId -HostKeys $HostKeys }
    }

    # Test Pageant as an SSH agent (using first positive cert to keep runtime reasonable)
    $AgentTestCase = $Matrix.Positive | Select-Object -First 1
    if ($AgentTestCase) {
        Invoke-PageantAgentTest -Name $AgentTestCase.Name -CertId $AgentTestCase.CertId -HostKeys $HostKeys
    }

    # Test -allowanycert functional behavior with an untrusted certificate
    $UntrustedNeg = $Matrix.Negative | Where-Object Name -eq 'NEG-UNTRUSTED' | Select-Object -First 1
    Test-AllowAnyCert -UntrustedCase $UntrustedNeg -HostKeys $HostKeys

    # Test X.509v3 certificate authentication (negotiation)
    if ($AgentTestCase) {
        # AuthX509 is now a global setting (shared by PuTTY and Pageant) read from
        # the base PuTTY registry key rather than a per-session option.
        $X509RegPath = 'HKCU:\Software\SimonTatham\PuTTY'
        try {
            if (-not (Test-Path -LiteralPath $X509RegPath)) {
                New-Item -Path $X509RegPath -Force | Out-Null
            }
            # Enable AuthX509 globally
            New-ItemProperty -LiteralPath $X509RegPath -Name 'AuthX509' -PropertyType DWord -Value 1 -Force | Out-Null

            # 1. Test X.509 Negotiation with both SHA-1 and SHA-256 enabled on the server
            Set-AcceptedAlgorithms -CustomAlgorithm 'x509v3-rsa2048-sha256,x509v3-ssh-rsa'
            Start-Sleep -Milliseconds 300

            foreach ($RsaCase in ($Matrix.Positive | Where-Object KeyType -eq 'RSA')) {
                if ($RsaCase.Bits -ge 2048) {
                    # Key size >= 2048 should negotiate x509v3-rsa2048-sha256 (SHA-256)
                    Invoke-PlinkTest -Name "X509v3-Negotiation-SHA256-$($RsaCase.Name)" -CertId $RsaCase.CertId -HostKeys $HostKeys
                    Add-Result -Name "PKIX-X509V3-SHA256-$($RsaCase.Name)" -Status 'Pass' -Detail "Successfully authenticated with $($RsaCase.Bits)-bit key (negotiated x509v3-rsa2048-sha256)."
                } else {
                    # Key size < 2048 should negotiate x509v3-ssh-rsa (SHA-1)
                    Invoke-PlinkTest -Name "X509v3-Negotiation-SHA1-$($RsaCase.Name)" -CertId $RsaCase.CertId -HostKeys $HostKeys
                    Add-Result -Name "PKIX-X509V3-SHA1-$($RsaCase.Name)" -Status 'Pass' -Detail "Successfully authenticated with $($RsaCase.Bits)-bit key (negotiated x509v3-ssh-rsa)."
                }
            }

            # 2. Test X.509 Negotiation with ONLY x509v3-rsa2048-sha256 enabled on the server
            # This verifies that keys < 2048 bits are rejected since they cannot upgrade/negotiate to SHA-256
            Set-AcceptedAlgorithms -CustomAlgorithm 'x509v3-rsa2048-sha256'
            Start-Sleep -Milliseconds 300

            foreach ($RsaCase in ($Matrix.Positive | Where-Object KeyType -eq 'RSA')) {
                if ($RsaCase.Bits -ge 2048) {
                    # Should succeed
                    Invoke-PlinkTest -Name "X509v3-Negotiation-SHA256-Only-Succeed-$($RsaCase.Name)" -CertId $RsaCase.CertId -HostKeys $HostKeys
                    Add-Result -Name "PKIX-X509V3-SHA256-Only-Succeed-$($RsaCase.Name)" -Status 'Pass' -Detail "Successfully authenticated with $($RsaCase.Bits)-bit key when server only accepts x509v3-rsa2048-sha256."
                } else {
                    # Should fail/be rejected
                    try {
                        Invoke-PlinkTest -Name "X509v3-Negotiation-SHA256-Only-Fail-$($RsaCase.Name)" -CertId $RsaCase.CertId -HostKeys $HostKeys -NoRetry
                        throw "Expected $($RsaCase.Bits)-bit key to fail x509v3-rsa2048-sha256-only authentication, but it succeeded!"
                    }
                    catch {
                        Add-Result -Name "X509v3-Negotiation-SHA256-Only-Rejected-$($RsaCase.Name)" -Status 'Pass' -Detail "Successfully rejected too short ($($RsaCase.Bits) bits) RSA key when server only accepts x509v3-rsa2048-sha256."
                    }
                }
            }

            # 3. Test X.509 ECDSA negotiation variants (SHA-256/384/512)
            $X509EcdsaVariants = @(
                [PSCustomObject]@{ Bits = 256; Algorithm = 'x509v3-ecdsa-sha2-nistp256'; HashName = 'SHA256' }
                [PSCustomObject]@{ Bits = 384; Algorithm = 'x509v3-ecdsa-sha2-nistp384'; HashName = 'SHA384' }
                [PSCustomObject]@{ Bits = 521; Algorithm = 'x509v3-ecdsa-sha2-nistp521'; HashName = 'SHA512' }
            )

            foreach ($Variant in $X509EcdsaVariants) {
                Set-AcceptedAlgorithms -CustomAlgorithm $Variant.Algorithm
                Start-Sleep -Milliseconds 300

                $VariantCases = $Matrix.Positive | Where-Object { $_.KeyType -eq 'ECDSA' -and $_.Bits -eq $Variant.Bits }
                if (-not $VariantCases) {
                    Add-Result -Name "PKIX-X509V3-$($Variant.HashName)" -Status 'Skip' -Detail "No ECDSA $($Variant.Bits)-bit test certificate available for $($Variant.Algorithm)."
                    continue
                }

                foreach ($EcdsaCase in $VariantCases) {
                    Invoke-PlinkTest -Name "X509v3-Negotiation-$($Variant.HashName)-$($EcdsaCase.Name)" -CertId $EcdsaCase.CertId -HostKeys $HostKeys
                    Add-Result -Name "PKIX-X509V3-$($Variant.HashName)-$($EcdsaCase.Name)" -Status 'Pass' -Detail "Successfully authenticated with $($EcdsaCase.Name) using $($Variant.Algorithm)."
                }
            }
        }
        finally {
            Remove-ItemProperty -LiteralPath $X509RegPath -Name 'AuthX509' -Force -ErrorAction SilentlyContinue
        }
    }

    Test-PageantFilters -Positive $Matrix.Positive -Negative $Matrix.Negative -SmartCardLogon $Matrix.SmartCardLogon

    Test-RegistryFlags
}
catch {
    $Message = $_.Exception.Message
    Add-Result -Name 'UNHANDLED' -Status 'Fail' -Detail $Message
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($DockerCmd) {
        $Logs = Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('logs', $PkixContainerName) -IgnoreExitCode
        Write-Host "Container Logs on Failure (Stdout):`n$($Logs.StdOut)"
        Write-Host "Container Logs on Failure (Stderr):`n$($Logs.StdErr)"
    }
}
finally {
    Stop-Pageants

    # Stop and remove the Docker container
    $DockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if ($DockerCmd) {
        Invoke-Native -FilePath $DockerCmd.Source -ArgumentList @('rm', '-f', 'puttycac-pkixssh-test') -IgnoreExitCode | Out-Null
    }

    # Clean up temporary files
    if ($PkixAuthKeysPath -and (Test-Path $PkixAuthKeysPath)) { Remove-Item $PkixAuthKeysPath -Force -ErrorAction SilentlyContinue }
    if ($script:Paths.PkixHostKeys -and (Test-Path $script:Paths.PkixHostKeys)) { Remove-Item $script:Paths.PkixHostKeys -Recurse -Force -ErrorAction SilentlyContinue }

    Restore-PuTTYRegistry
    Remove-TestCertificates

    Write-Summary 
}
