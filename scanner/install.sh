#!/bin/sh
# lysec installer.
#
#   curl -fsSL https://sec.ly2u.com/install.sh | sh
#
# Downloads the secwatch scanner from GitHub Releases, verifies the release
# signature (minisign, or OpenSSL 3 when minisign is absent) and the SHA-256
# checksum, and copies the binary into place, with a short command lysec
# pointing to it when no other program uses that name. It changes nothing
# else and does not run a scan.
#
# Environment:
#   SECWATCH_VERSION        release tag, e.g. v0.1.0 (default: latest)
#   SECWATCH_INSTALL_DIR    target directory (default: /usr/local/bin as root,
#                           otherwise ~/.local/bin)
#   SECWATCH_DOWNLOAD_BASE  alternative download location (mirror)
#   SECWATCH_VERIFY         auto (default) | minisign | openssl

# Release signing key. Also published as keys/release-signing.pub in the repo.
KEY_ID='C7A3F417E9543893'
KEY_ID_RAW='933854e917f4a3c7'
MINISIGN_PUB='RWSTOFTpF/Sjx2fTAEQxNY5fo2IVpUt/2h+SRqBTalrVx0qmvEE/OEi6'
PUB_PEM='MCowBQYDK2VwAyEAZ9MARDE1jl+jYhWlS3/aH5JGoFNqWtXHSqa8QT84SLo='

RELEASES='https://github.com/ly2u/sec/releases'

say() { printf '%s\n' "$*" >&2; }
die() {
	say "错误：$*"
	exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # URL FILE
	case "$1" in
	https://*) ;;
	file://*) ;;
	*) die "下载地址必须是 https：$1" ;;
	esac
	if have curl; then
		curl -fsSL --retry 2 -o "$2" "$1" || die "下载失败：$1"
	elif have wget; then
		wget -q -O "$2" "$1" || die "下载失败：$1"
	else
		die "需要 curl 或 wget"
	fi
}

sha256() { # FILE -> hex
	if have sha256sum; then
		sha256sum "$1" | cut -d' ' -f1
	elif have shasum; then
		shasum -a 256 "$1" | cut -d' ' -f1
	elif have openssl; then
		openssl dgst -sha256 -r "$1" | cut -d' ' -f1
	else
		die "需要 sha256sum、shasum 或 openssl 来校验文件"
	fi
}

openssl_ok() {
	have openssl || return 1
	case "$(openssl version 2>/dev/null)" in
	"OpenSSL "[3-9].*) return 0 ;;
	*) return 1 ;;
	esac
}

# Prints the trusted comment on success; exits on any failure.
verify_signature() { # DIR
	sums="$1/SHA256SUMS"
	sig="$1/SHA256SUMS.minisig"
	mode=${SECWATCH_VERIFY:-auto}
	if [ "$mode" = auto ]; then
		if have minisign; then
			mode=minisign
		elif openssl_ok; then
			mode=openssl
		else
			die "无法校验签名：请先安装 minisign（apt/dnf/apk install minisign）或 OpenSSL 3，再重新运行"
		fi
	fi
	case "$mode" in
	minisign)
		have minisign || die "未找到 minisign"
		minisign -Vm "$sums" -x "$sig" -P "$MINISIGN_PUB" -Q || die "签名校验失败，已中止"
		;;
	openssl)
		openssl_ok || die "需要 OpenSSL 3 或更高版本"
		d="$1/verify"
		mkdir "$d"
		printf -- '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' "$PUB_PEM" >"$d/key.pem"
		[ "$(sed -n 1p "$sig" | cut -c1-19)" = "untrusted comment: " ] || die "签名文件格式不对"
		sed -n 2p "$sig" | openssl base64 -d -A >"$d/sig" 2>/dev/null || die "签名文件格式不对"
		[ "$(wc -c <"$d/sig" | tr -d ' ')" = 74 ] || die "签名文件格式不对"
		[ "$(head -c 2 "$d/sig")" = ED ] || die "签名算法不对"
		[ "$(head -c 10 "$d/sig" | tail -c 8 | od -An -tx1 | tr -d ' \n')" = "$KEY_ID_RAW" ] ||
			die "签名不是由 lysec 发布密钥 $KEY_ID 生成的"
		tail -c 64 "$d/sig" >"$d/sig.bin"
		openssl dgst -blake2b512 -binary "$sums" >"$d/digest" || die "OpenSSL 不支持 BLAKE2b"
		openssl pkeyutl -verify -pubin -inkey "$d/key.pem" -rawin -in "$d/digest" -sigfile "$d/sig.bin" \
			>/dev/null 2>&1 || die "签名校验失败，已中止"
		line3=$(sed -n 3p "$sig")
		comment=${line3#trusted comment: }
		[ "$comment" != "$line3" ] || die "签名文件格式不对"
		sed -n 4p "$sig" | openssl base64 -d -A >"$d/global" 2>/dev/null || die "签名文件格式不对"
		{
			cat "$d/sig.bin"
			printf '%s' "$comment"
		} >"$d/global.msg"
		openssl pkeyutl -verify -pubin -inkey "$d/key.pem" -rawin -in "$d/global.msg" -sigfile "$d/global" \
			>/dev/null 2>&1 || die "签名附带的说明校验失败，已中止"
		printf '%s\n' "$comment"
		;;
	*) die "SECWATCH_VERIFY 只能是 auto、minisign 或 openssl" ;;
	esac
}

main() {
	[ "$(uname -s)" = Linux ] || die "secwatch 只支持 Linux"
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "暂不支持此 CPU 架构：$(uname -m)" ;;
	esac
	asset="secwatch-linux-$arch"
	version=${SECWATCH_VERSION:-latest}
	if [ -n "${SECWATCH_DOWNLOAD_BASE:-}" ]; then
		base=${SECWATCH_DOWNLOAD_BASE%/}
	elif [ "$version" = latest ]; then
		base="$RELEASES/latest/download"
	else
		base="$RELEASES/download/$version"
	fi
	if [ -n "${SECWATCH_INSTALL_DIR:-}" ]; then
		dir=$SECWATCH_INSTALL_DIR
	elif [ "$(id -u)" = 0 ]; then
		dir=/usr/local/bin
	else
		dir="$HOME/.local/bin"
	fi

	tmp=$(mktemp -d 2>/dev/null) || die "无法创建临时目录"
	trap 'rm -rf "$tmp"' EXIT
	trap 'rm -rf "$tmp"; exit 1' INT TERM

	say "下载 $asset（$version）……"
	fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"
	fetch "$base/SHA256SUMS.minisig" "$tmp/SHA256SUMS.minisig"
	fetch "$base/$asset" "$tmp/$asset"

	comment=$(verify_signature "$tmp") || exit 1
	case "$comment" in
	"secwatch release="*" file=SHA256SUMS") ;;
	*) die "签名说明不符合预期：$comment" ;;
	esac
	signed=${comment#secwatch release=}
	signed=${signed%% *}
	if [ "$version" != latest ] && [ "$signed" != "$version" ]; then
		die "要求的版本是 $version，下载到的签名版本却是 $signed，已中止"
	fi
	say "签名有效：lysec 发布密钥 $KEY_ID，版本 $signed"

	expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
	[ -n "$expected" ] || die "校验清单中没有 $asset"
	actual=$(sha256 "$tmp/$asset")
	[ "$actual" = "$expected" ] || die "$asset 的 SHA-256 与签名清单不一致，已中止"

	mkdir -p "$dir" 2>/dev/null || die "无法创建 $dir（需要 root 时请用 sudo 运行，或设置 SECWATCH_INSTALL_DIR）"
	cp "$tmp/$asset" "$dir/.secwatch.new.$$" 2>/dev/null ||
		die "无法写入 $dir（需要 root 时请用 sudo 运行，或设置 SECWATCH_INSTALL_DIR）"
	chmod 0755 "$dir/.secwatch.new.$$"
	mv -f "$dir/.secwatch.new.$$" "$dir/secwatch" || die "无法写入 $dir/secwatch"

	say "已安装：$("$dir/secwatch" version) -> $dir/secwatch"

	# Short command lysec -> secwatch, unless the name is taken by anything.
	short=lysec
	if [ -L "$dir/$short" ] && [ "$(readlink "$dir/$short")" = secwatch ]; then
		:
	elif [ -e "$dir/$short" ] || [ -L "$dir/$short" ] || have "$short"; then
		say "提示：$short 已被其他程序占用，没有创建短命令，请使用 secwatch。"
		short=""
	elif ! ln -s secwatch "$dir/$short" 2>/dev/null; then
		short=""
	fi

	name=${short:-secwatch}
	case ":$PATH:" in
	*":$dir:"*) cmd=$name ;;
	*)
		cmd="$dir/$name"
		say "提示：$dir 不在 PATH 中"
		;;
	esac
	say ""
	sudo="sudo "
	[ "$(id -u)" = 0 ] && sudo=""
	say "打开菜单（立即检查、查看详情、定时检查与 Telegram 通知、更新）："
	say "  ${sudo}$cmd"
	say "或者直接检查（只读，不修改系统、不上传数据）："
	say "  ${sudo}$cmd scan"
}

main "$@"
