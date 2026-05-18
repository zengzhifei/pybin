# pybin

运维工具 CLI 和 Python SDK，支持 macOS / Linux。

## 安装

### 在线安装

```sh
curl -LsSf https://raw.githubusercontent.com/zengzhifei/pybin/main/install.sh | bash
```

或手动：

```sh
git clone https://github.com/zengzhifei/pybin.git
cd pybin
./setup.sh
```

### 离线安装

从 [Releases](https://github.com/zengzhifei/pybin/releases) 下载对应平台的 `pybin-*.tar.gz`，解压后执行：

```sh
tar xzf pybin-*.tar.gz
cd pybin
./setup.sh
```

包内已内置 Python 环境和依赖。如果系统有更小版本的 python3，setup.sh 会优先使用系统 Python（兼容老系统 glibc）。

## 更新

重新下载离线包覆盖，或：

```sh
cd pybin
git pull
./setup.sh --force
```

## 卸载

```sh
pybin --uninstall
```

## 功能

- **信息** — 版本、Python 信息、本机 IP
- **Shell** — 配置重载、智能目录跳转
- **数据库** — MySQL、Redis、Elasticsearch 连接与查询
- **服务器管理** — Go / Java 服务启停
- **SSH** — 单机/批量 SSH
- **Git** — 推送、分支清理、cherry-pick 等
- **文件** — 安全删除、目录排序、文件追踪、Excel 读写
- **文本** — 大小写转换、grep、哈希、CRC32 等
- **部署** — HTTP 文件服务、文件分发
- **安全** — AES 加解密、Git Hook 加解密
- **其他** — 日期计算、消息推送、邮件发送等

## SDK

pybin 安装后在 `~/.pybin/pybinlib/` 下提供 Python SDK，第三方扩展可直接导入：

```python
from pybinlib import sdk
from pybinlib.ann import RuntimeEnv, runtime, RuntimeKey
```

`PYTHONPATH` 已自动包含 `~/.pybin/`，无需额外配置。

### 编写扩展

扩展模块需定义一个 `cli.py`，使用 `@runtime` 装饰器声明命令。然后在 `~/.pybin_config.json` 中注册路径：

```json
{
  "pybin": {
    "extend_clis": ["/path/to/your/cli.py"]
  }
}
```

重新执行 `./setup.sh`（或 `python3 pybin/install.py`）即可安装扩展命令。

## 开发

```sh
# 安装依赖并部署
./setup.sh

# 仅提交代码
make push

# 发布新版本
make release
```

## License

MIT
