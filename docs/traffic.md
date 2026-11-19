# 本地网卡筛选和流量倍率

Linux Agent 可在实例自己的 `config.conf` 中启用本地计量。关闭 Agent 后编辑配置，再用原服务启动。默认实例、`-instance=NAME` 和 `-config=FILE` 沿用原有路径。未设置 `TRAFFIC_*` 时，沿用上游的采集、网卡选择和更新行为。

```ini
INTERFACE="wan0,relay0,backup0"
TRAFFIC_REPORT="billing"
TRAFFIC_EXCLUDE="backup0"
TRAFFIC_WEIGHTS="wan0:1000000:0:0:1000000;relay0:0:0:1000000:2000000"
```

`INTERFACE` 使用逗号分隔的完整接口名。`TRAFFIC_EXCLUDE` 优先于选择和倍率，排除后至少保留一张网卡。Worker 下发的其他动态配置照常生效，计量始终使用本地的接口列表、排除项、倍率和模式。

`TRAFFIC_WEIGHTS` 的每项依次为 `网卡:RX→入站:TX→入站:RX→出站:TX→出站`，多项用分号分隔。倍率用整数 ppm（百万分之一）表示，`500000` 对应 0.5 倍，`2000000` 对应 2 倍。未指定倍率的选中接口按 `1000000:0:0:1000000` 处理。上例的计费出站增量为 `Δwan0.TX + Δrelay0.RX + 2 × Δrelay0.TX`。

## 采样和上报

每次采样分别计算各接口 RX/TX 的增量，再应用倍率。每张卡的四个方向映射各自保存不足一字节的余数，后续采样继续使用。接口身份变化时重新建立基线。单方向计数回落时，另一方向仍可正常累计。

任何选中的网卡缺失或采集失败时，冻结累计并使旧基线失效。恢复时首组样本仅建立新基线。缺卡和排除均保留已经产生的小数余数。修改选择、倍率或报告模式后的首次样本同样重新建立基线，累计历史保持原值。

| 上报字段 | 扩展启用后的值 |
| --- | --- |
| `net_rx`、`net_tx` | 连续累计字节数。`raw` 加入实际增量，`billing` 加入加权增量。 |
| `net_rx_monthly`、`net_tx_monthly` | 原生月统计基于上述连续累计值更新，仍使用 `traffic.dat` 和 `RESET_DAY`。 |
| `net_in_speed`、`net_out_speed` | 已选接口的实际 RX/TX 速率，单位为字节/秒。 |

本地 `traffic-accounting.dat` 同时保存原始、计费和已上报口径的累计、接口基线与余数。账本在全量上报、首次检测到基线失效、每隔约 30 秒的采样和正常退出时原子写入。对外累计值取自已写入的账本，速率取自当前采样。Agent 在同一系统启动周期内重启时，可以继续使用仍有效的持久基线。

## 检查和迁移

```sh
cf-probe traffic-check -instance=example
cf-probe traffic-status -instance=example
```

`traffic-check` 验证本地策略和选中网卡。`traffic-status` 显示已写入的账本和当前策略是否匹配。两条命令只在本地读取数据。也可用 `-config=FILE` 指定配置文件。

新的实例可直接建立基线。已有 `traffic.dat` 的实例需要先停止 Agent 并备份配置及流量文件，然后设置本地策略并运行 `traffic-check`。准备一个以字节为单位的初始值文件，例如：

```json
{
  "raw_total_bytes": {"rx": 100, "tx": 200},
  "billing_total_bytes": {"rx": 100, "tx": 200},
  "reported_total_bytes": {"rx": 100, "tx": 200}
}
```

用实例自己的 `traffic.dat` 中的 `RX_PREV` / `TX_PREV` 填写 `reported_total_bytes`，让原生月统计从同一原点继续累计。`raw_total_bytes` 和 `billing_total_bytes` 填写已核实的连续累计初始值。设置好文件后执行：

```sh
cf-probe traffic-seed -instance=example -seed=/path/seed.json
cf-probe traffic-status -instance=example
```

播种只创建缺失的账本，保留原生月统计文件。使用自定义路径启动时，播种也应使用相同的 `-instance` 和 `-config`。迁移完成后可启动 Agent。回滚时先停止 Agent，再成套恢复备份的配置、状态和二进制。

启用扩展时，上游二进制自更新和旧版 `rx_correction` / `tx_correction` 校正入口会被拒绝，避免替换账本实现或将原始接口计数写入月统计基线。
