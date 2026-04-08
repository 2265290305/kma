# Shanzi

Build:

```sh
cd /home/shanzi/kernel_workspace/kernel_platform/hello_ko
make
```

Load and unload:

```sh
insmod Shanzi.ko
dmesg | tail
rmmod Shanzi
```

If your kernel build output is not in `common/out`, override `KDIR`:

```sh
make KDIR=/path/to/kernel/out
```
