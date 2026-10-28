# SPDX-License-Identifier: MIT
#
# In every Ignition Java runtime on this machine, including the runtimes a
# gateway hands out to Designers and Vision Clients, removes eMudhra's root
# certificates and Sectigo's AAA Certificate Services root from cacerts.
# Run from an elevated PowerShell. Pass extra install folders as arguments if
# Ignition or a launcher is installed somewhere non-default.
#
#   powershell -ExecutionPolicy Bypass -File .\remove-emudhra-roots.ps1 [D:\Ignition ...]
#Requires -RunAsAdministrator

# Added to a gateway's runtime version so clients download the patched runtime
# instead of reusing a cached one. Change it whenever a runtime fixed by an
# earlier version of this script needs changing again, along with the shell
# script and the folder name in README.md's "Check that it worked".
# Digits only: older launchers reject any other character in a version.
$runtimeSuffix = '20261028'

$roots = @("$env:ProgramFiles\Inductive Automation")
foreach ($user in Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue) {
  $roots += "$($user.FullName)\.ignition"
  $roots += "$($user.FullName)\AppData\Roaming\Inductive Automation"
  # A redirect.txt in a user's .ignition folder moves that user's cache to the
  # folder on its first line. Read it literally, as the launchers do.
  $redirect = "$($user.FullName)\.ignition\redirect.txt"
  if (Test-Path $redirect) {
    $dir = Get-Content $redirect -TotalCount 1 -Encoding UTF8 -ErrorAction SilentlyContinue
    if ($dir) { $roots += $dir }
  }
}
$roots += $args

# SHA-256 fingerprints of the roots to remove: the four Oracle lists (see
# https://ops.java/emudhra), emSign ECC Root CA - G3 and AAA Certificate
# Services, which the compromised intermediates chain to, and emSign Root CA -
# G1 and G2; and eMudhra's other two roots, emSign Root CA - C1 and emSign ECC
# Root CA - C3, which only older runtimes have. Removing the roots, rather than
# blocking the compromised intermediates by fingerprint, also stops re-encoded
# copies of them. Roots are matched by fingerprint because older Ignition
# runtimes use different aliases. Older runtimes don't have G2.
$rootFingerprints = @(
  '86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B',
  'D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4',
  '40F6AF0346A99AA1CD1D555A4E9CCE62C7F9634603EE406615833DC8C8D00367',
  '1AA0C2709E831BD6E3B5129A00BA41F7EEEF020872F1E6504BF0F6C3F24F3AF3',
  '125609AA301DA0A249B97A8239CB6A34216F44DCAC9F3954B14292F2E8C8608F',
  'BC4D809B15189D78DB3E1D8CF4F9726A795DA1643CA5F1358E1DDB0EDC0D7EB3'
)

# Runs keytool with the java at $Java against the trust store at $Keystore.
# English output keeps the labels Get-RootAlias reads stable.
function Invoke-Keytool([string]$Java, [string]$Keystore, [string[]]$Arguments) {
  # Quoted because PowerShell splits an unquoted -Dname.with.dots=value argument.
  $output = & $Java '-Duser.language=en' '-Duser.country=US' -m java.base/sun.security.tools.keytool.Main @Arguments -keystore $Keystore -storepass changeit 2>$null
  if ($LASTEXITCODE -ne 0) { throw "keytool failed with $Java" }
  return $output
}

# Returns the keytool listing of the trust store at $Keystore. An unreadable or
# empty store must not pass as one without our roots.
function Get-TrustStoreList([string]$Java, [string]$Keystore) {
  $list = @(Invoke-Keytool $Java $Keystore @('-list', '-v'))
  if (-not ($list -match '^Alias name: ')) { throw "couldn't read $Keystore" }
  return $list
}

# Returns the aliases of our roots in the trust store at $Keystore.
function Get-RootAlias([string]$Java, [string]$Keystore) {
  $alias = $null
  foreach ($line in (Get-TrustStoreList $Java $Keystore)) {
    if ($line -match '^Alias name: (.*)$') {
      $alias = $Matches[1]
    } elseif ($line -match '^\s*SHA256: (\S+)' -and $script:rootFingerprints -contains ($Matches[1] -replace ':', '')) {
      $alias
    }
  }
}

function Get-EntryCount([string]$Java, [string]$Keystore) {
  return @((Get-TrustStoreList $Java $Keystore) -match '^Alias name: ').Count
}

# Deletes $Aliases from the trust store at $Keystore, then checks none of our
# roots is left.
function Remove-RootAlias([string]$Java, [string]$Keystore, [string[]]$Aliases) {
  foreach ($alias in $Aliases) { $null = Invoke-Keytool $Java $Keystore @('-delete', '-alias', $alias) }
  if (@(Get-RootAlias $Java $Keystore).Count -ne 0) { throw 'roots still present after deleting them' }
}

# Replaces the file at $Path with $Path.new by renaming, so nothing reading it,
# such as a running gateway, ever sees it half-written, even if the script is
# interrupted. Replace keeps the original's permissions. NullString passes a
# real null: PowerShell turns $null into "" for a string parameter, which
# Replace rejects.
function Move-NewOver([string]$Path) {
  [IO.File]::Replace("$Path.new", $Path, [NullString]::Value)
}

# Removes our roots from the cacerts of the runtime at $Runtime, keeping the
# original as cacerts.orig. The roots are deleted from a copy, which then
# replaces it. Returns $false when they were already gone.
function Remove-Root([string]$Runtime) {
  $java = Join-Path $Runtime 'bin\java.exe'
  $ks = Join-Path $Runtime 'lib\security\cacerts'
  $aliases = @(Get-RootAlias $java $ks)
  if ($aliases.Count -eq 0) { return $false }
  if (-not (Test-Path "$ks.orig")) { Copy-Item $ks "$ks.orig" -ErrorAction Stop }
  try {
    Copy-Item $ks "$ks.new" -Force -ErrorAction Stop
    Remove-RootAlias $java "$ks.new" $aliases
    Move-NewOver $ks
  } finally {
    Remove-Item "$ks.new" -Force -ErrorAction SilentlyContinue
  }
  return $true
}

$failed = 0
foreach ($root in $roots | Where-Object { Test-Path $_ }) {
  # Runtimes are found by their cacerts, next to a bin\java.exe.
  Get-ChildItem $root -Recurse -File -Filter 'cacerts' -ErrorAction SilentlyContinue |
    Where-Object { $_.DirectoryName -like '*\lib\security' } |
    ForEach-Object {
      $ks = $_.FullName
      $runtime = Split-Path (Split-Path $_.DirectoryName -Parent) -Parent
      if (-not (Test-Path (Join-Path $runtime 'bin\java.exe'))) { return }
      # -ErrorAction Stop turns a failed step into an exception, so a runtime
      # that can't be backed up or written is reported and skipped instead of
      # being reported as patched.
      try {
        if (Remove-Root $runtime) { Write-Output "removed roots: $ks" } else { Write-Output "roots already removed: $ks" }
      } catch {
        Write-Warning "failed: $ks ($($_.Exception.Message))"
        $script:failed++
      }
    }
}

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
function Read-Exactly($Stream, [byte[]]$Buffer, [long]$Count) {
  $offset = 0
  while ($offset -lt $Count) {
    $n = $Stream.Read($Buffer, $offset, $Count - $offset)
    if ($n -le 0) { throw 'archive ends early' }
    $offset += $n
  }
}

function Copy-Exactly($From, $To, [long]$Count) {
  $buffer = New-Object byte[] 65536
  while ($Count -gt 0) {
    $n = $From.Read($buffer, 0, [int][Math]::Min($Count, $buffer.Length))
    if ($n -le 0) { throw 'archive ends early' }
    $To.Write($buffer, 0, $n)
    $Count -= $n
  }
}

# Tar headers are 512-byte blocks: name at 0, size (octal) at 124, checksum at
# 148, type at 156, and in POSIX ustar a name prefix at 345.
function Get-TarName([byte[]]$Block) {
  $name = [Text.Encoding]::ASCII.GetString($Block, 0, 100).Split([char]0)[0]
  if ([Text.Encoding]::ASCII.GetString($Block, 257, 6) -eq "ustar`0") {
    $prefix = [Text.Encoding]::ASCII.GetString($Block, 345, 155).Split([char]0)[0]
    if ($prefix) { $name = "$prefix/$name" }
  }
  return $name
}

function Get-TarSize([byte[]]$Block) {
  if ($Block[124] -band 0x80) { throw 'unsupported tar size field' }
  $octal = [Text.Encoding]::ASCII.GetString($Block, 124, 12).Trim([char]0, ' ')
  if ($octal -eq '') { return [long]0 }
  return [Convert]::ToInt64($octal, 8)
}

function Set-TarSize([byte[]]$Block, [long]$Size) {
  $octal = [Text.Encoding]::ASCII.GetBytes([Convert]::ToString($Size, 8).PadLeft(11, '0'))
  [Array]::Copy($octal, 0, $Block, 124, 11)
  $Block[135] = 0
  for ($i = 148; $i -lt 156; $i++) { $Block[$i] = 32 }
  $sum = 0
  foreach ($b in $Block) { $sum += $b }
  $octal = [Text.Encoding]::ASCII.GetBytes([Convert]::ToString($sum, 8).PadLeft(6, '0'))
  [Array]::Copy($octal, 0, $Block, 148, 6)
  $Block[154] = 0
  $Block[155] = 32
}

function Test-ZeroBlock([byte[]]$Block) {
  foreach ($b in $Block) { if ($b -ne 0) { return $false } }
  return $true
}

# Walks the .tar.gz at $Path and returns its entry count and the bytes of the
# entries named in $Names that it has. When $OutFile is given, also writes a copy in which
# every block is copied unchanged except the content (and size and checksum)
# of the entries in $Replace, a table of entry name to new bytes.
function Copy-TarGz([string]$Path, [string[]]$Names, [hashtable]$Replace, [string]$OutFile) {
  $in = New-Object IO.Compression.GZipStream([IO.File]::OpenRead($Path), [IO.Compression.CompressionMode]::Decompress)
  $out = $null
  if ($OutFile) {
    $out = New-Object IO.Compression.GZipStream([IO.File]::Create($OutFile), [IO.Compression.CompressionLevel]::Optimal)
  }
  try {
    $block = New-Object byte[] 512
    $result = @{ Count = 0; Members = @{} }
    # Text of the pax header just before this entry, or 'GNU' after a GNU
    # long-name header, which could override the entry's name or size.
    $previous = $null
    while ($true) {
      Read-Exactly $in $block 512
      if (Test-ZeroBlock $block) {
        if ($out) {
          $out.Write($block, 0, 512)
          $in.CopyTo($out)
        }
        break
      }
      $result.Count++
      $type = [char]$block[156]
      $size = Get-TarSize $block
      $padded = [long][Math]::Ceiling($size / 512) * 512
      $name = Get-TarName $block
      if (($type -eq '0' -or $block[156] -eq 0) -and $Names -contains $name) {
        # The size written below is in the main header, so it must not be
        # overridden by a header before it. (pax mtime records are fine.)
        if ($previous -eq 'GNU' -or $previous -match '(^|\n)\d+ (size|path)=') {
          throw "extended header overrides the size or name of $name"
        }
        $data = New-Object byte[] $padded
        Read-Exactly $in $data $padded
        $content = New-Object byte[] $size
        [Array]::Copy($data, $content, $size)
        $result.Members[$name] = $content
        if ($out -and $Replace.ContainsKey($name)) {
          $bytes = $Replace[$name]
          Set-TarSize $block $bytes.Length
          $out.Write($block, 0, 512)
          $out.Write($bytes, 0, $bytes.Length)
          $pad = [long][Math]::Ceiling($bytes.Length / 512) * 512 - $bytes.Length
          $out.Write((New-Object byte[] $pad), 0, $pad)
        } elseif ($out) {
          $out.Write($block, 0, 512)
          $out.Write($data, 0, $padded)
        }
      } elseif ($type -eq 'x') {
        $data = New-Object byte[] $padded
        Read-Exactly $in $data $padded
        if ($out) {
          $out.Write($block, 0, 512)
          $out.Write($data, 0, $padded)
        }
      } else {
        if ($out) {
          $out.Write($block, 0, 512)
          Copy-Exactly $in $out $padded
        } else {
          Copy-Exactly $in ([IO.Stream]::Null) $padded
        }
      }
      $previous = if ($type -eq 'x') { [Text.Encoding]::UTF8.GetString($data, 0, $size) } elseif ($type -in 'L', 'K') { 'GNU' } else { $null }
    }
    return $result
  } finally {
    $in.Dispose()
    if ($out) { $out.Dispose() }
  }
}

# Returns the entry count and names of the .zip at $Path, and the bytes of the
# entries named in $Names that it has.
function Read-Zip([string]$Path, [string[]]$Names) {
  $zip = [IO.Compression.ZipFile]::OpenRead($Path)
  try {
    $result = @{ Count = $zip.Entries.Count; Names = ($zip.Entries | ForEach-Object { $_.FullName }) -join "`n"; Members = @{} }
    foreach ($n in $Names) {
      $entry = $zip.GetEntry($n)
      if (-not $entry) { continue }
      $stream = $entry.Open()
      try {
        $buffer = New-Object IO.MemoryStream
        $stream.CopyTo($buffer)
        $result.Members[$n] = $buffer.ToArray()
      } finally {
        $stream.Dispose()
      }
    }
    return $result
  } finally {
    $zip.Dispose()
  }
}

# Copies the .zip at $Path to $OutFile and rewrites the entries in $Replace, a
# table of entry name to new bytes, in place, so entry order is unchanged.
function Update-Zip([string]$Path, [hashtable]$Replace, [string]$OutFile) {
  Copy-Item $Path $OutFile -Force -ErrorAction Stop
  $zip = [IO.Compression.ZipFile]::Open($OutFile, [IO.Compression.ZipArchiveMode]::Update)
  try {
    foreach ($name in $Replace.Keys) {
      $stream = $zip.GetEntry($name).Open()
      try {
        $stream.SetLength(0)
        $stream.Write($Replace[$name], 0, $Replace[$name].Length)
      } finally {
        $stream.Dispose()
      }
    }
  } finally {
    $zip.Dispose()
  }
}

# Returns the java of the gateway's own runtime in the lib\runtime folder at
# $Dir. It edits the cacerts inside the archives, whichever OS they are for.
function Get-GatewayJava([string]$Dir) {
  foreach ($sub in Get-ChildItem $Dir -Directory) {
    $java = Join-Path $sub.FullName 'bin\java.exe'
    if (Test-Path $java) {
      $null = & $java -version 2>$null
      if ($LASTEXITCODE -eq 0) { return $java }
    }
  }
  throw "no Java runtime in $Dir to edit the cacerts inside with"
}

# Patches the runtime inside one archive: removes our roots from its cacerts,
# using the java at $Java. The result is checked before it replaces the
# original, which is kept as .orig. Returns $true when the archive needed no
# change.
function Update-Archive([IO.FileInfo]$Archive, [string]$Java) {
  $top = $Archive.Name -replace '\.(tar\.gz|zip)$', ''
  $ca = "$top/lib/security/cacerts"
  $isZip = $Archive.Name -like '*.zip'
  $new = "$($Archive.FullName).new"
  $ks = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
  try {
    $before = if ($isZip) { Read-Zip $Archive.FullName @($ca) } else { Copy-TarGz $Archive.FullName @($ca) @{} $null }
    if (-not $before.Members.ContainsKey($ca)) { throw "no $ca inside" }
    [IO.File]::WriteAllBytes($ks, $before.Members[$ca])
    $aliases = @(Get-RootAlias $Java $ks)
    $entryCount = Get-EntryCount $Java $ks
    if ($aliases.Count -eq 0) { return $true }

    Remove-RootAlias $Java $ks $aliases
    $replace = @{ $ca = [IO.File]::ReadAllBytes($ks) }
    if ($isZip) {
      Update-Zip $Archive.FullName $replace $new
      $after = Read-Zip $new @($ca)
      if ($after.Names -ne $before.Names) { throw 'entries changed' }
    } else {
      $null = Copy-TarGz $Archive.FullName @($ca) $replace $new
      $after = Copy-TarGz $new @($ca) @{} $null
      if ($after.Count -ne $before.Count) { throw 'entry count changed' }
    }
    if (-not $after.Members.ContainsKey($ca)) { throw 'cacerts missing after patching' }
    [IO.File]::WriteAllBytes($ks, $after.Members[$ca])
    if (@(Get-RootAlias $Java $ks).Count -ne 0 -or (Get-EntryCount $Java $ks) -ne $entryCount - $aliases.Count) {
      throw 'unexpected cacerts content after patching'
    }

    if (-not (Test-Path "$($Archive.FullName).orig")) { Copy-Item $Archive.FullName "$($Archive.FullName).orig" -ErrorAction Stop }
    # A client downloading the archive meanwhile gets either the whole old one
    # or the whole new one.
    Move-NewOver $Archive.FullName
    return $false
  } finally {
    Remove-Item $new, $ks -Force -ErrorAction SilentlyContinue
  }
}

# Returns the version in $Dir\version before this script (Base) and with
# $runtimeSuffix added (New). The base version always comes from version.orig
# once it exists, so a rerun or a new suffix never stacks suffixes.
function Get-RuntimeVersion([string]$Dir) {
  $v = Join-Path $Dir 'version'
  $basePath = if (Test-Path "$v.orig") { "$v.orig" } else { $v }
  $base = Get-Content $basePath -TotalCount 1 -ErrorAction Stop
  if ($base -notmatch '^[0-9.]+$') { throw "unexpected version '$base'" }
  return @{ Base = $base; New = "$base.$script:runtimeSuffix" }
}

# Sets the version in the file at $Path to $New, keeping the original as
# $Path.orig.
function Set-VersionFile([string]$Path, [string]$New) {
  if ((Get-Content $Path -TotalCount 1 -ErrorAction Stop) -eq $New) {
    Write-Output "runtime version already ${New}: $Path"
    return
  }
  if (-not (Test-Path "$Path.orig")) { Copy-Item $Path "$Path.orig" -ErrorAction Stop }
  Copy-Item $Path "$Path.new" -Force -ErrorAction Stop
  Set-Content "$Path.new" $New -NoNewline -Encoding Ascii -ErrorAction Stop
  Move-NewOver $Path
  Write-Output "runtime version set to ${New}: $Path"
}

# True when the cacerts of the runtime at $Runtime has none of our roots left.
function Test-RuntimeFixed([string]$Runtime) {
  try {
    $java = Join-Path $Runtime 'bin\java.exe'
    return @(Get-RootAlias $java (Join-Path $Runtime 'lib\security\cacerts')).Count -eq 0
  } catch {
    return $false
  }
}

# A gateway hands Designers and Vision Clients the runtimes in
# lib\runtime\jre-*.tar.gz and jre-*.zip, and they cache each one under the
# version in lib\runtime\version. Patch every archive, then change the version
# so clients download the patched runtime. The version only changes once every
# archive is patched: a gateway reinstalls its own runtime from its archive
# when the version changes, unless its runtime folder is marked below, and
# would get the roots back from an unpatched one.
foreach ($root in $roots | Where-Object { Test-Path $_ }) {
  Get-ChildItem $root -Recurse -File -Filter 'version' -ErrorAction SilentlyContinue |
    Where-Object { $_.DirectoryName -like '*\lib\runtime' } |
    ForEach-Object {
      $dir = $_.DirectoryName
      $archives = @(Get-ChildItem $dir -File | Where-Object { $_.Name -like 'jre-*.tar.gz' -or $_.Name -like 'jre-*.zip' })
      if ($archives.Count -eq 0) { return }
      $allPatched = $true
      $gatewayJava = $null
      foreach ($archive in $archives) {
        try {
          if (-not $gatewayJava) { $gatewayJava = Get-GatewayJava $dir }
          if (Update-Archive $archive $gatewayJava) {
            Write-Output "already patched: $($archive.FullName)"
          } else {
            Write-Output "patched: $($archive.FullName)"
          }
        } catch {
          Write-Warning "failed: $($archive.FullName) ($($_.Exception.Message))"
          $allPatched = $false
          $script:failed++
        }
      }
      if ($allPatched) {
        try {
          $versions = Get-RuntimeVersion $dir
          Set-VersionFile (Join-Path $dir 'version') $versions.New
        } catch {
          Remove-Item (Join-Path $dir 'version.new') -Force -ErrorAction SilentlyContinue
          Write-Warning "failed: $(Join-Path $dir 'version') ($($_.Exception.Message))"
          $script:failed++
          return
        }
        # Write the new version into the gateway's own runtime folder too. The
        # gateway's startup scripts reinstall that folder from its archive when
        # its version differs, which would drop changes made inside it, such as
        # certificates added to its cacerts, and the .orig files. The folder is
        # only marked when it was at the archives' version, or at a version an
        # earlier run of this script set, and is already fixed. Otherwise, such
        # as right after an upgrade the gateway hasn't started from yet, the
        # gateway reinstalls it from the patched archive.
        $folders = Get-ChildItem $dir -Directory | Where-Object {
          -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and (Test-Path (Join-Path $_.FullName 'version'))
        }
        foreach ($folder in $folders) {
          $sv = Join-Path $folder.FullName 'version'
          try {
            $current = Get-Content $sv -TotalCount 1 -ErrorAction Stop
            if ($current -eq $versions.New) {
              Write-Output "runtime version already $($versions.New): $sv"
            } elseif (($current -eq $versions.Base -or $current -match "^$([regex]::Escape($versions.Base))\.[0-9]{8}$") -and
              (Test-RuntimeFixed $folder.FullName)) {
              Set-VersionFile $sv $versions.New
            } else {
              Write-Output "left for the gateway to reinstall from its patched archive: $($folder.FullName)"
            }
          } catch {
            Remove-Item "$sv.new" -Force -ErrorAction SilentlyContinue
            Write-Warning "failed: $sv ($($_.Exception.Message))"
            $script:failed++
          }
        }
      } else {
        Write-Warning "failed: $(Join-Path $dir 'version') (left unchanged because a runtime above wasn't patched)"
        $script:failed++
      }
    }
}

if ($failed -gt 0) {
  Write-Warning 'Some runtimes were not patched; see the failed lines above.'
  exit 1
}
