$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$visualStudio = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$visualStudio) {
    throw 'The Visual Studio C++ tools for x86 are required.'
}
$developerShell = Join-Path $visualStudio 'Common7\Tools\Launch-VsDevShell.ps1'
& $developerShell -Arch x86 -HostArch amd64 -SkipAutomaticLocation

$temp = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) "fish-aead-test-$([Guid]::NewGuid())")
$originalConfig = $env:OPENSSL_CONF
Push-Location $temp.FullName
try {
    & cl.exe /nologo /EHsc /std:c++20 /W4 /DFISH_AEAD_TEST /Fe:aead-test.exe "/I$repo\include" "/I$repo\fish_10\src" `
        "$PSScriptRoot\aead-test.cpp" "$repo\fish_10\src\aead.cpp" /link "/LIBPATH:$repo\lib" libcrypto.lib
    if ($LASTEXITCODE -ne 0) {
        throw 'The native AEAD test did not compile.'
    }

    Copy-Item -LiteralPath "$repo\lib\libcrypto-3.dll" -Destination $temp.FullName
    $env:OPENSSL_CONF = Join-Path $temp.FullName 'openssl.cnf'
    Set-Content -LiteralPath $env:OPENSSL_CONF -Value '# Isolate provider tests from machine configuration.' -Encoding ascii
    & .\aead-test.exe
    if ($LASTEXITCODE -ne 0) {
        throw 'The native AEAD test failed.'
    }
    & .\aead-test.exe --state-boundaries
    if ($LASTEXITCODE -ne 0) {
        throw 'The native AEAD state boundary test failed.'
    }
    & .\aead-test.exe --unavailable-provider
    if ($LASTEXITCODE -ne 0) {
        throw 'The native AEAD unavailable-provider test failed.'
    }

    # A fresh process starts its counter at zero and allocates a new OS-seeded session.
    $headers = foreach ($run in 1..2) {
        $frame = & .\aead-test.exe --first-frame
        if ($LASTEXITCODE -ne 0) {
            throw "Could not generate a first frame in process $run."
        }
        $base64 = $frame.Substring('+FISH-AEAD1 '.Length, 32).Replace('-', '+').Replace('_', '/')
        $header = [Convert]::FromBase64String($base64)
        if ($header[16..23] -ne 0) {
            throw "Process $run did not start its counter at zero."
        }
        [Convert]::ToHexString($header[0..15])
    }
    if ($headers[0] -eq $headers[1]) {
        throw 'Separate processes reused the same AEAD session.'
    }
    Write-Host 'FiSH AEAD process restart test passed'
}
finally {
    $env:OPENSSL_CONF = $originalConfig
    Pop-Location
    Get-ChildItem -LiteralPath $temp.FullName -File | Remove-Item
    Remove-Item -LiteralPath $temp.FullName
}
