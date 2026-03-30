#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PATCH_DIR="${PATCH_DIR:-${REPO_ROOT}/SukiSU_patch/kpm}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/out/Final-Image-Find}"
ANYKERNEL_IMAGE="${ANYKERNEL_IMAGE:-${REPO_ROOT}/AnyKernel3/Image}"
GKI_DEFCONFIG="${GKI_DEFCONFIG:-${REPO_ROOT}/common/arch/arm64/configs/gki_defconfig}"

if [[ -f "${GKI_DEFCONFIG}" ]]; then
  if grep -q '^CONFIG_KPM=' "${GKI_DEFCONFIG}"; then
    sed -i 's/^CONFIG_KPM=.*/CONFIG_KPM=y/' "${GKI_DEFCONFIG}"
  else
    printf '\nCONFIG_KPM=y\n' >> "${GKI_DEFCONFIG}"
  fi

  if grep -q '^CONFIG_KSU=' "${GKI_DEFCONFIG}"; then
    sed -i 's/^CONFIG_KSU=.*/CONFIG_KSU=y/' "${GKI_DEFCONFIG}"
  else
    printf 'CONFIG_KSU=y\n' >> "${GKI_DEFCONFIG}"
  fi
else
  echo "gki_defconfig not found: ${GKI_DEFCONFIG}" >&2
  exit 1
fi

if [[ ! -d "${PATCH_DIR}" ]]; then
  echo "PATCH_DIR not found: ${PATCH_DIR}" >&2
  exit 1
fi

if [[ ! -d "${OUT_DIR}" ]]; then
  echo "OUT_DIR not found: ${OUT_DIR}" >&2
  exit 1
fi

mkdir -p "$(dirname "${ANYKERNEL_IMAGE}")"

cd "${OUT_DIR}"
cp "${PATCH_DIR}/patch_linux" .
chmod +x patch_linux
./patch_linux
rm -f Image
mv oImage Image
cp Image "${ANYKERNEL_IMAGE}"
