# rex-discover

一个命令扫出 Tailscale tailnet + 局域网里所有活着的 Rex 服务。

## 用法

```bash
cargo build --release
./target/release/rex-discover              # 默认 tailnet + 局域网
./target/release/rex-discover --lan-only
./target/release/rex-discover --tailnet-only --json
./target/release/rex-discover --cidr 192.168.1.0/24
./target/release/rex-discover add --dry-run
./target/release/rex-discover add          # 一键 rex hosts add 到本地
```

选项: `--all`(含离线节点)、`--concurrency N`、`--timeout SECS`、`--cidr CIDR`(可重复)。

## 依赖：`rex` 自动发现

握手和 `add` 都需要本机有 `rex` CLI。解析顺序：

1. 环境变量 **`REX_BIN`**（若设置且可执行，直接用它）
2. **`PATH`** 里的 `rex`
3. **macOS**：自动在 app 包内探测
   - `/Applications/Rex*.app/Contents/Helpers/*.rex/Contents/MacOS/rex`
   - `$HOME/Applications/Rex*.app/...`（同样路径）
4. 都找不到才报错，并提示安装或设置 `REX_BIN`

所以装了 Rex.app / Rex Beta.app 的 Mac 不必再手动软链。需要覆盖时：

```bash
export REX_BIN="/Applications/Rex Beta.app/Contents/Helpers/Rex Server.rex/Contents/MacOS/rex"
```

`tailscale` 仍要求在 `PATH` 里（仅做 tailnet 扫描时）。

## 原理

- **tailnet**: 读 `tailscale status --json` 拿节点,逐个 `rex -S <addr> ls` 真握手(443 和 7297 都试),输出含 `LABEL` 即判定活着。
- **局域网**: 自动推断本机私有网段,先 TCP 快探 443/7297 端口,只对开口的 IP 再握手。
