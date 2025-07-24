# InterCloud eXpress (ICX)

![ICX Logo](./assets/icx.png)

## Notes

On Debian you might need to create this symlink to fix bpf compilation issues:

```shell
sudo ln -sf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm
```