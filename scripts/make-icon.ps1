# Generates src\OW2RG.App\Assets\app.ico (a shield with a ring of stars) from code, so the icon is reproducible.
# Windows PowerShell 5.1 / System.Drawing. No downloads.
param([string]$Out = (Join-Path $PSScriptRoot '..\src\OW2RG.App\Assets\app.ico'))
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

function New-IconPng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = $size / 256.0
    # Shield outline
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $pts = @(
        (New-Object System.Drawing.PointF (128*$s), (14*$s)),
        (New-Object System.Drawing.PointF (226*$s), (48*$s)),
        (New-Object System.Drawing.PointF (218*$s), (150*$s)),
        (New-Object System.Drawing.PointF (128*$s), (244*$s)),
        (New-Object System.Drawing.PointF (38*$s), (150*$s)),
        (New-Object System.Drawing.PointF (30*$s), (48*$s))
    )
    $path.AddPolygon($pts)
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush ((New-Object System.Drawing.PointF 0, 0), (New-Object System.Drawing.PointF 0, $size), ([System.Drawing.Color]::FromArgb(255, 37, 99, 235)), ([System.Drawing.Color]::FromArgb(255, 17, 38, 94)))
    $g.FillPath($brush, $path)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 249, 158, 26)), ([Math]::Max(1.5, 10*$s))
    $pen.LineJoin = 'Round'
    $g.DrawPath($pen, $path)
    # Ring of 12 stars (Europe)
    $star = [System.Drawing.Color]::FromArgb(255, 255, 214, 10)
    $sb = New-Object System.Drawing.SolidBrush $star
    $cx = 128*$s; $cy = 122*$s; $r = 62*$s; $sr = [Math]::Max(1.2, 11*$s)
    for ($i = 0; $i -lt 12; $i++) {
        $a = [Math]::PI * 2 * $i / 12 - [Math]::PI / 2
        $x = $cx + $r * [Math]::Cos($a); $y = $cy + $r * [Math]::Sin($a)
        $sp = @()
        for ($k = 0; $k -lt 10; $k++) {
            $rad = if ($k % 2 -eq 0) { $sr } else { $sr * 0.45 }
            $b = [Math]::PI * 2 * $k / 10 - [Math]::PI / 2
            $sp += New-Object System.Drawing.PointF ([single]($x + $rad * [Math]::Cos($b))), ([single]($y + $rad * [Math]::Sin($b)))
        }
        $g.FillPolygon($sb, [System.Drawing.PointF[]]$sp)
    }
    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return ,$ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$images = $sizes | ForEach-Object { ,(New-IconPng $_) }
$fs = [System.IO.File]::Create([System.IO.Path]::GetFullPath($Out))
$w = New-Object System.IO.BinaryWriter $fs
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]; $len = $images[$i].Length
    $w.Write([byte]($(if ($sz -ge 256) { 0 } else { $sz }))); $w.Write([byte]($(if ($sz -ge 256) { 0 } else { $sz })))
    $w.Write([byte]0); $w.Write([byte]0); $w.Write([UInt16]1); $w.Write([UInt16]32)
    $w.Write([UInt32]$len); $w.Write([UInt32]$offset)
    $offset += $len
}
foreach ($img in $images) { $w.Write($img) }
$w.Close()
Write-Host "Wrote $Out"
