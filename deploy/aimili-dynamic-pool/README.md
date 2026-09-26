# AimiliVPN 动态代理池

该服务在回环地址提供一个 SOCKS5 入口，并根据 AimiliVPN 槽位状态选择可用出口。
入口认证由 AimiliVPN 的 `slots.json` 动态提供：管理后台配置动态池账号密码后，
入口将在短周期内切换到 USER/PASSWORD 模式；槽位账号密码用于动态池连接对应槽位。

- 默认监听：`127.0.0.1:17928`
- 不修改现有 `aimili-vpngate -> 127.0.0.1:7928`
- `config.validation.json` 使用验证容器的 `/data/slots.json`
- 生产环境应将 `state_command` 切换到独立的 AimiliVPN 多出口实例

3x-ui 只需新增一个 SOCKS outbound：

```json
{
  "tag": "aimili-dynamic-pool",
  "protocol": "socks",
  "settings": {
    "servers": [{"address": "127.0.0.1", "port": 17928, "users": [{"user": "admin", "pass": "admin2012"}]}]
  }
}
```

验证部署的 `in-10083-tcp` 是内部 canary：它绑定 `172.17.0.1:10083`，默认不加入现有
订阅，也不直接暴露公网。Clash Verge Rev 拉取现有订阅时看不到它是预期行为。

若要正式加入订阅，必须同时完成两项变更：

1. 将 `in-10083-tcp` 关联到目标 3x-ui client 的 `client_inbounds`。
2. 确认 Nginx/Cloudflare WebSocket 路径 `/ws-isp-7899-7f4d9c2a` 已指向
   `172.17.0.1:10083`，并重新拉取订阅。

这两项属于线上配置变更，执行前应先备份 x-ui 数据库和 Nginx 配置；当前验证栈没有自动
执行，避免影响原有订阅节点。

## 3x-ui 增量回滚

`scripts/rollback_xui_dynamic_pool.py` 只删除本次新增的 `in-10083-tcp`、
`aimili-dynamic-pool` 和对应路由，并保留原有 `aimili-vpngate`。先在副本上执行
dry-run，再对线上数据库和 runtime JSON 执行实际回滚：

```bash
python3 scripts/rollback_xui_dynamic_pool.py \
  --db /path/to/x-ui.db \
  --runtime /path/to/runtime.json \
  --dry-run
python3 scripts/rollback_xui_dynamic_pool.py \
  --db /path/to/x-ui.db \
  --runtime /path/to/runtime.json
systemctl restart x-ui
```

回滚前保留 `x-ui.db`、模板配置和 runtime JSON 备份；服务重启由运维命令显式执行，
脚本本身不会触碰 systemd 或其它服务。
