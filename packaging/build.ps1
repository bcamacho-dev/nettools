$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$version = "0.1.0"
New-Item -ItemType Directory -Force -Path (Join-Path $root "dist") | Out-Null

foreach ($arch in @("amd64", "arm64")) {
	$env:GOOS = "linux"
	$env:GOARCH = $arch
	$env:CGO_ENABLED = "0"
	$bin = Join-Path $root "dist\nettools-linux-$arch"
	go build -trimpath -ldflags "-s -w" -o $bin (Join-Path $root "cmd\nettools")
	if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
	Remove-Item Env:GOOS
	Remove-Item Env:GOARCH
	Remove-Item Env:CGO_ENABLED
	$deb = Join-Path $root "dist\nettools_${version}_${arch}.deb"
	go run (Join-Path $root "packaging\mkdeb") -version $version -arch $arch -binary $bin -root $root -out $deb
	if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
