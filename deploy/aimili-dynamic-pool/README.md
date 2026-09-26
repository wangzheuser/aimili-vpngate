# AimiliVPN 动态代理池

该服务根据 AimiliVPN 槽位状态选择可用出口，并可同时供宿主机、Docker 网络和公网客户端使用。
入口认证由 AimiliVPN 的 `slots.json` 动态提供：管理后台配置动态池账号密码后，
入口将在短周期内切换到 USER/PASSWORD 模式；槽位账号密码用于动态池连接对应槽位。

- 默认验证监听：`0.0.0.0:17928`
- 槽位监听：`0.0.0.0:17929-17992`
- 公网监听必须配合 SOCKS5 用户名/密码和防火墙来源限制
- `config.validation.json` 使用验证容器的 `/data/slots.json`
- 生产环境应将 `state_command` 切换到独立的 AimiliVPN 多出口实例

3x-ui 在与动态池同机时仍可使用回环地址；Docker 容器应使用宿主机网关地址或
`host.docker.internal` 访问 `17928` 和槽位端口。3x-ui 只需新增一个 SOCKS outbound：

```json
{
  "tag": "aimili-dynamic-pool",
  "protocol": "socks",
  "settings": {
    "servers": [{"address": "127.0.0.1", "port": 17928, "users": [{"user": "admin", "pass": "admin2012"}]}]
  }
}
```

公网部署时设置 `SLOT_PROXY_HOST=0.0.0.0` 作为监听地址，并设置
`SLOT_PROXY_ADVERTISE_HOST` 为服务器公网 IP 或 DNS，避免订阅中出现不可连接的
`0.0.0.0`。同时开放 TCP `7928`、`17928`、`17929-17992`，并在云安全组和主机
防火墙中限制来源；不要使用 `docker compose down` 影响其它服务。

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
