#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${WORKSPACE_ROOT:-$(cd "${REPO_ROOT}/.." && pwd)}"

SUSFS_META="${SUSFS_META:-}"
KANDROID_VERSION="${KANDROID_VERSION:-android15}"
KERNEL_VERSION="${KERNEL_VERSION:-6.6}"
SUSFS_DEV="${SUSFS_DEV:-false}"
FILE_INPUT="${FILE_INPUT:-}"
KV2="${KV2:-}"
KV3="${KV3:-}"
ZRAM_INPUT="${ZRAM_INPUT:-}"
GITHUB_WORKSPACE_DIR="${GITHUB_WORKSPACE:-$(cd "${REPO_ROOT}/.." && pwd)}"
GITHUB_OUTPUT_FILE="${GITHUB_OUTPUT:-/dev/null}"
GKI_DEFCONFIG="${GKI_DEFCONFIG:-${REPO_ROOT}/common/arch/arm64/configs/gki_defconfig}"

set_kernel_config() {
  local key="$1"
  local value="$2"

  if grep -q "^${key}=" "$GKI_DEFCONFIG"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$GKI_DEFCONFIG"
  else
    echo "${key}=${value}" >> "$GKI_DEFCONFIG"
  fi
}

if [[ ! -f "$GKI_DEFCONFIG" ]]; then
  echo "gki_defconfig not found: ${GKI_DEFCONFIG}" >&2
  exit 1
fi

if [[ "$SUSFS_META" != "-1" ]]; then
  set_kernel_config "CONFIG_KSU_SUSFS" "y"
  set_kernel_config "CONFIG_KSU_SUSFS_SUS_PATH" "y"
  set_kernel_config "CONFIG_KSU_SUSFS_SUS_MAP" "y"
  set_kernel_config "CONFIG_KSU_SUSFS_SUS_MOUNT" "y"
  set_kernel_config "CONFIG_KSU_SUSFS_SUS_KSTAT" "y"
  set_kernel_config "CONFIG_KSU_SUSFS_SPOOF_UNAME" "y"
  set_kernel_config "CONFIG_KSU_SUSFS_ENABLE_LOG" "y"
  set_kernel_config "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS" "y"
  set_kernel_config "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG" "y"
  set_kernel_config "CONFIG_KSU_SUSFS_OPEN_REDIRECT" "y"
else
  set_kernel_config "CONFIG_KSU_SUSFS" "n"
fi

if [[ "$SUSFS_META" != "-1" ]]; then
  susfs_branch="gki-${KANDROID_VERSION}-${KERNEL_VERSION}"
  if [[ "$SUSFS_DEV" == "true" ]]; then
    susfs_branch="${susfs_branch}-dev"
  fi
  if [[ -d susfs4ksu/.git ]]; then
    git -C susfs4ksu fetch --depth=1 origin "$susfs_branch"
    git -C susfs4ksu checkout -B "$susfs_branch" "origin/$susfs_branch"
  elif [[ -e susfs4ksu ]]; then
    echo "susfs4ksu exists but is not a git repo: $(pwd)/susfs4ksu" >&2
    exit 1
  else
    git clone --depth=1 https://gitlab.com/simonpunk/susfs4ksu.git -b "$susfs_branch"
  fi
  cd susfs4ksu
  if [[ -n "$SUSFS_META" ]]; then
    if [[ "$SUSFS_META" =~ ^[0-9]+$ ]]; then
      git checkout "HEAD~$SUSFS_META"
    else
      git checkout "$SUSFS_META"
    fi
  else
    echo "SUSFS_META 为空，使用最新上游 SUSFS"
  fi
  cd ..
fi

if [[ -d SukiSU_patch/.git ]]; then
  git -C SukiSU_patch fetch --depth=1 origin
  git -C SukiSU_patch checkout -B "$(git -C SukiSU_patch symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's|^origin/||' || echo main)" "origin/$(git -C SukiSU_patch symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's|^origin/||' || echo main)"
elif [[ -e SukiSU_patch ]]; then
  echo "SukiSU_patch exists but is not a git repo: $(pwd)/SukiSU_patch" >&2
  exit 1
else
  git clone --depth=1 https://github.com/ShirkNeko/SukiSU_patch.git
fi

if [[ -d Action-Build/.git ]]; then
  git -C Action-Build fetch --depth=1 origin
  git -C Action-Build checkout -B "$(git -C Action-Build symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's|^origin/||' || echo main)" "origin/$(git -C Action-Build symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's|^origin/||' || echo main)"
elif [[ -e Action-Build ]]; then
  echo "Action-Build exists but is not a git repo: $(pwd)/Action-Build" >&2
  exit 1
else
  git clone --depth=1 https://github.com/Numbersf/Action-Build.git
fi
cd kernel_platform

if [[ "$SUSFS_META" != "-1" ]]; then
  echo "正在拉取susfs补丁"
  cp ../susfs4ksu/kernel_patches/50_add_susfs_in_gki-${KANDROID_VERSION}-${KERNEL_VERSION}.patch ./common/
  cp ../susfs4ksu/kernel_patches/fs/* ./common/fs/
  cp ../susfs4ksu/kernel_patches/include/linux/* ./common/include/linux/
fi

if [[ "$ZRAM_INPUT" == 1* ]]; then
  echo "正在拉取zram补丁"
  cp -r ../SukiSU_patch/other/zram/lz4k/include/linux/* ./common/include/linux/
  cp -r ../SukiSU_patch/other/zram/lz4k/lib/* ./common/lib/
  cp -r ../SukiSU_patch/other/zram/lz4k/crypto/* ./common/crypto/
  cp -r ../SukiSU_patch/other/zram/lz4k_oplus ./common/lib/
fi

cd ./common
GKI_V="${KANDROID_VERSION}-${KERNEL_VERSION}"
SUBLEVEL=$(grep '^SUBLEVEL *=' Makefile | head -n1 | cut -d= -f2 | tr -d ' ')

if [[ "$GKI_V" == "android13-5.15" && "$SUBLEVEL" -lt 123 ]]; then
  echo "修复内核版本为5.15.0~5.15.123仅支持旧版C库造成的一些bug"
  cp ../../Action-Build/patches/fix_5.15.legacy ./fix_5.15.legacy.patch
  patch -p1 < fix_5.15.legacy.patch
  echo "fix_5.15_patch完成"
fi

if [[ "$KV2" == "66" && "$KV3" -le 6630 && "$SUSFS_META" != "-1" ]]; then
  TRUSTY_EXISTS="false"
  if grep -q 'common-modules/trusty' "$GITHUB_WORKSPACE_DIR/.repo/manifests_fallback/${FILE_INPUT}.xml"; then
    TRUSTY_EXISTS="true"
  fi
  echo "trusty_exists=$TRUSTY_EXISTS" >> "$GITHUB_OUTPUT_FILE"
  if [[ "$TRUSTY_EXISTS" == "false" ]]; then
    echo "修复内核版本为6.6.0~6.6.30的机型源码及清单中缺失TrustyOS导致的susfs报错"
    sed -i 's/-32,12 +32,38/-32,11 +32,37/g' 50_add_susfs_in_gki-${KANDROID_VERSION}-${KERNEL_VERSION}.patch
    sed -i '/#include <trace\/hooks\/fs.h>/d' 50_add_susfs_in_gki-${KANDROID_VERSION}-${KERNEL_VERSION}.patch
  fi
fi

if [[ "$SUSFS_META" != "-1" ]]; then
  fake_patched=0
  if [[ "$GKI_V" == "android15-6.6" ]]; then
    if ! grep -qxF $'\tunsigned int nr_subpages = __PAGE_SIZE / PAGE_SIZE;' ./fs/proc/task_mmu.c; then
      echo "未找到 nr_subpages，正在进行补丁修复"
      sed -i -e '/int ret = 0, copied = 0;/a \\tunsigned int nr_subpages \= __PAGE_SIZE \/ PAGE_SIZE;' -e '/int ret = 0, copied = 0;/a \\tpagemap_entry_t \*res = NULL;' ./fs/proc/task_mmu.c
      fake_patched=1
    fi
    if ! grep -qxF '#include <linux/dma-buf.h>' ./fs/proc/base.c; then
      echo "未找到 #include <linux/dma-buf.h>，添加缺失的头文件"
      sed -i '/#include <linux\/cpufreq_times.h>/a #include <linux\/dma-buf.h>' ./fs/proc/base.c
    fi
  fi
  if [[ "$GKI_V" == "android14-6.1" ]]; then
    if ! grep -qxF $'\tif (!vma_pages(vma))' ./fs/proc/task_mmu.c; then
      echo "未找到 vma_pages，正在进行补丁修复"
      fake_patched=1
    fi
    if ! grep -qxF '#include <linux/dma-buf.h>' ./fs/proc/base.c; then
      echo "未找到 #include <linux/dma-buf.h>，添加缺失的头文件"
      sed -i '/#include <linux\/cpufreq_times.h>/a #include <linux\/dma-buf.h>' ./fs/proc/base.c
    fi
  fi
  if [[ "$GKI_V" == "android12-5.10" || "$GKI_V" == "android13-5.15" ]]; then
    if ! grep -qxF $'\tif (!vma_pages(vma))' ./fs/proc/task_mmu.c; then
      echo "未找到 vma_pages，正在进行补丁修复"
      fake_patched=1
    fi
  fi

  echo "正在打susfs补丁"
  patch -N -p1 --forward < 50_add_susfs_in_gki-${KANDROID_VERSION}-${KERNEL_VERSION}.patch || true
  echo "susfs_patch完成"

  if [[ "$fake_patched" == 1 ]]; then
    if [[ "$GKI_V" == "android15-6.6" ]]; then
      if grep -qxF $'\tunsigned int nr_subpages = __PAGE_SIZE / PAGE_SIZE;' ./fs/proc/task_mmu.c; then
        sed -i -e '/unsigned int nr_subpages \= __PAGE_SIZE \/ PAGE_SIZE;/d' -e '/pagemap_entry_t \*res = NULL;/d' ./fs/proc/task_mmu.c
      fi
    fi
    if [[ "$GKI_V" == "android12-5.10" || "$GKI_V" == "android13-5.15" || "$GKI_V" == "android14-6.1" ]]; then
      if grep -q 'goto[[:space:]]\+show_pad;' ./fs/proc/task_mmu.c; then
        sed -i -e 's/goto show_pad;/return 0;/' ./fs/proc/task_mmu.c
      fi
    fi
  fi
fi
