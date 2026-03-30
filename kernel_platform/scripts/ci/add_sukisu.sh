#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${WORKSPACE_DIR:-$REPO_ROOT}"

MANAGER_BRANCH="${MANAGER_BRANCH:-main}"
KSU_META="${KSU_META:-builtin/shanzi/}"
GITHUB_ENV_FILE="${GITHUB_ENV:-/tmp/github_env}"

if [[ "$(grep -o '/' <<<"$KSU_META" | wc -l)" -lt 2 ]]; then
  echo "错误: KSU_META 参数缺少必要的分隔符 '/'，格式应为: 分支名/自定义标识(可省略)/提交hash(可省略)"
  exit 10
fi

IFS='/' read -r BRANCH_NAME CUSTOM_TAG MANUAL_HASH <<<"$KSU_META"

echo "分支名: $BRANCH_NAME"
[[ -n "$CUSTOM_TAG" ]] && echo "自定义版本标识: $CUSTOM_TAG" || echo "自定义版本标识: 未启用"
[[ -n "$MANUAL_HASH" ]] && echo "手动指定 hash: $MANUAL_HASH" || echo "手动指定 hash: 未启用"

curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/${MANAGER_BRANCH}/kernel/setup.sh" | bash -s "$BRANCH_NAME"
cd ./KernelSU

if [[ -n "$MANUAL_HASH" ]]; then
  git fetch origin "$BRANCH_NAME" --depth=50
  git checkout "$MANUAL_HASH"
  SHORT_HASH=${MANUAL_HASH:0:8}
fi

KSU_API_VERSION=$(curl -fsSL "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/$BRANCH_NAME/kernel/Kbuild" |
  grep -m1 "KSU_VERSION_API :=" | awk -F'= ' '{print $2}' | tr -d '[:space:]')
if [[ -z "$KSU_API_VERSION" || "$(printf '%s\n' "$KSU_API_VERSION" "3.1.7" | sort -V | head -n1)" != "3.1.7" ]]; then
  KSU_API_VERSION="3.1.7"
fi
echo "KSU_API_VERSION=$KSU_API_VERSION" >>"$GITHUB_ENV_FILE"

GIT_HASH=$(git rev-parse --short HEAD)
echo "GIT_HASH=$GIT_HASH"

if [[ -n "${MANUAL_HASH:-}" ]]; then
  USE_HASH="$SHORT_HASH"
else
  USE_HASH="$GIT_HASH"
fi

if [[ -z "$CUSTOM_TAG" ]]; then
  VERSION_FULL="v$KSU_API_VERSION-$USE_HASH@$BRANCH_NAME"
else
  VERSION_FULL="v$KSU_API_VERSION-$CUSTOM_TAG@$BRANCH_NAME[$USE_HASH]"
fi

sed -i '/define get_ksu_version_full/,/endef/d' kernel/Kbuild
sed -i '/KSU_VERSION_API :=/d' kernel/Kbuild
sed -i '/KSU_VERSION_FULL :=/d' kernel/Kbuild

VERSION_DEFINITIONS=$(
  cat <<EOF
define get_ksu_version_full
$VERSION_FULL
endef

KSU_VERSION_API := $KSU_API_VERSION
KSU_VERSION_FULL := $VERSION_FULL
EOF
)

awk -v def="$VERSION_DEFINITIONS" '
  /REPO_OWNER :=/ {print; print def; inserted=1; next}
  1
  END {if (!inserted) print def}
' kernel/Kbuild >kernel/Kbuild.tmp && mv kernel/Kbuild.tmp kernel/Kbuild

KSU_VERSION=$(expr $(git rev-list --count "$MANAGER_BRANCH" 2>/dev/null || echo 13000) + 37185)
echo "KSUVER=$KSU_VERSION" >>"$GITHUB_ENV_FILE"

echo "::group::最终 Kbuild 中版本信息及部分调试结果预览"
grep -A10 "REPO_OWNER" kernel/Kbuild
grep "KSU_VERSION_FULL" kernel/Kbuild
echo "::endgroup::"
