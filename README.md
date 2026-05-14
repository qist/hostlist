# hostlist

## 概述

`hostlist` 是一个 CoreDNS 插件，使用 [AdGuard HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry) 格式的规则进行 DNS 域名过滤。支持黑名单/白名单两种模式，远程规则自动同步，本地缓存。

插件在 `tsig` 之后执行，优先级高于测速、缓存等插件。

## 特性

- 支持 AdGuard 全部 DNS 过滤规则格式
- 黑名单模式（封锁匹配域名）和白名单模式（仅放行匹配域名）
- 远程 URL 和本地文件两种规则来源
- 定时自动同步远程规则，支持本地缓存
- 反向标签 trie 数据结构，50 万+ 域名毫秒级匹配
- 用户自定义黑白名单，不受远程更新影响
- 客户端 IP 白名单，指定 IP 绕过家长控制和安全搜索

## Corefile 语法

```
hostlist {
    url <remote-url>              # 远程规则 URL（可重复）
    file <local-path>             # 本地规则文件（可重复）
    whitelist_url <remote-url>    # 远程白名单 URL（可重复）
    whitelist_file <local-path>   # 本地白名单文件（可重复）
    allowlist <rule>              # 用户白名单规则（可重复）
    blocklist <rule>              # 用户黑名单规则（可重复）
    mode blacklist|whitelist      # 模式，默认 blacklist
    block_type 0.0.0.0|nxdomain|empty  # 拦截响应类型，默认 0.0.0.0
    safesearch on|off             # 安全搜索，默认 off
    parental on|off               # 家长控制，默认 off
    bypass_ip <ip/cidr>           # 客户端 IP 白名单，绕过家长控制和安全搜索（可重复）
    refresh <duration>            # 远程同步间隔，默认 4d
    cache_dir <path>              # 缓存目录，默认 ./hostlist/
}
```

## 示例配置

### 基础配置

```
. {
    hostlist {
        url https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
        url https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt
        file /etc/coredns/custom_blocklist.txt
        refresh 12h
    }
    forward . 8.8.8.8:53
}
```

### 完整配置

```
. {
    hostlist {
        # 黑名单来源
        url https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
        url https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt
        file /etc/coredns/custom_blocklist.txt

        # 白名单来源（整份文件所有规则作为白名单）
        whitelist_url https://example.com/my_allowlist.txt
        whitelist_file /etc/coredns/allowlist.txt

        # 用户自定义规则（不受远程更新影响）
        allowlist @@||www.youtube.com^
        allowlist @@||m.youtube.com^
        blocklist ||ads.example.com^
        blocklist ||tracker.myapp.com^

        # 设置
        mode blacklist
        block_type nxdomain
        parental off
        safesearch off
        bypass_ip 192.168.1.100
        bypass_ip 10.0.0.0/24
        bypass_ip 172.16.0.0/16
        refresh 12h
        cache_dir /var/lib/coredns/hostlist
    }
    forward . 8.8.8.8:53
    log
}
```

### 白名单模式

```
. {
    hostlist {
        url https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
        mode whitelist
    }
    forward . 8.8.8.8:53
}
```

白名单模式下，仅放行规则列表中的域名，其他全部拦截。

### 家长控制 + 安全搜索 + IP 白名单

```
. {
    hostlist {
        parental on
        safesearch on
        bypass_ip 192.168.1.100
        bypass_ip 10.0.0.0/24
        bypass_ip 172.16.0.0/16
    }
    forward . 8.8.8.8:53
}
```

`bypass_ip` 指定的客户端 IP 不受家长控制拦截和安全搜索重写限制，其他客户端正常过滤。

## 规则格式

### 封锁规则

| 格式 | 示例 | 说明 |
|------|------|------|
| `\|\|domain^` | `\|\|ads.example.com^` | 封锁域名及所有子域名 |
| `127.0.0.1 domain` | `127.0.0.1 analytics.163.com` | 仅封锁精确域名，不含子域名 |
| `/REGEX/` | `/^ads\d*\./` | 正则匹配封锁 |
| `\|\|*wild*domain^` | `\|\|*serror*.wo.com.cn^` | 通配符，自动转正则 |
| `.domain^` | `.bbelements.com^` | 封锁域名及子域名 |
| `domain` | `wykop.pl` | 封锁域名 |

### 白名单规则

| 格式 | 示例 | 说明 |
|------|------|------|
| `@@\|\|domain^` | `@@\|\|youtube.com^` | 放行域名及所有子域名 |
| `@@\|domain^` | `@@\|affiliate.notion.so^` | 放行（单锚点） |
| `@@\|\|domain^\|` | `@@\|\|sedge.nfl.com^\|` | 放行（末尾多余 `\|`） |
| `@@/REGEX/` | `@@/^safe\./` | 正则匹配放行 |

### 修饰符

| 修饰符 | 行为 |
|--------|------|
| `$important` | 正常处理（剥离修饰符） |
| `$badfilter` | 跳过（禁用其他规则，不适用） |
| `$dnsrewrite` | 跳过（DNS 重写，不适用） |

### 注释

```
! 这是注释
# 这也是注释
```

## 行为说明

### 黑名单模式（默认）

- 匹配 `url`/`file` 中的封锁规则 → 拦截
- 匹配 `@@`/`whitelist_url`/`whitelist_file` 中的白名单规则 → 放行
- 匹配 `allowlist` 中的用户白名单 → 放行
- 匹配 `blocklist` 中的用户黑名单 → 拦截
- 白名单优先级高于黑名单
- 其他域名 → 放行

### 白名单模式

- 匹配 `url`/`file` 中的规则 → 放行
- 其他域名 → 拦截

### 拦截响应

- `block_type 0.0.0.0`（默认）：返回 NOERROR + A 记录 `0.0.0.0`
- `block_type nxdomain`：返回 NXDOMAIN + SOA
- `block_type empty`：返回 NOERROR，无应答记录

### 域名匹配

- `||domain^` 格式：祖先匹配，封锁 `domain` 及所有子域名
- hosts 格式（`127.0.0.1 domain`）：精确匹配，仅封锁 `domain` 本身
- 白名单 `@@||domain^`：祖先匹配，放行 `domain` 及所有子域名

### 远程同步

- 启动时立即加载所有规则
- 按 `refresh` 间隔定时重新下载远程规则
- 下载失败时使用本地缓存文件
- 所有错误（网络超时、文件不存在等）均跳过，不影响进程

## 安全搜索

`safesearch on` 强制搜索引擎使用安全模式，将查询重写到安全搜索域名。

```
. {
    hostlist {
        safesearch on
    }
    forward . 8.8.8.8:53
}
```

支持的搜索引擎：

| 引擎 | 重写目标 |
|------|---------|
| Google（190+ 国家域名） | `forcesafesearch.google.com` |
| Bing | `strict.bing.com` |
| YouTube | `restrict.youtube.com` |
| DuckDuckGo | `safe.duckduckgo.com` |
| Brave | `safesearch.brave.com` |
| Ecosia | `strict-safe-search.ecosia.org` |
| Yandex | `213.180.193.56` |
| Pixabay | `safesearch.pixabay.com` |
| Qwant | `safeapi.qwant.com` |

查询 `www.google.com` 时返回 CNAME `forcesafesearch.google.com`，客户端会自动解析到 Google 安全搜索。

## 家长控制

`parental on` 自动加载赌博和恶意软件过滤列表。

```
. {
    hostlist {
        parental on
    }
    forward . 8.8.8.8:53
}
```

启用后自动加载：
- 赌博网站
- 恶意软件
- NSFW网站

## 客户端 IP 白名单

`bypass_ip` 指定客户端 IP 或 CIDR 网段，这些客户端发起的 DNS 查询将绕过家长控制拦截和安全搜索重写，直接放行。

```
. {
    hostlist {
        parental on
        safesearch on
        bypass_ip 192.168.1.100       # 单个 IP
        bypass_ip 10.0.0.0/24         # CIDR 网段
        bypass_ip 2001:db8::/32       # IPv6 网段
    }
    forward . 8.8.8.8:53
}
```

适用场景：
- 家庭网络中，家长设备不受限制，孩子设备受家长控制和安全搜索保护
- 企业内部，管理设备绕过过滤，员工设备正常过滤
- 支持 IPv4 和 IPv6 地址，支持 CIDR 网段格式

## 缓存目录

远程下载的规则会保存到 `cache_dir` 目录（默认 `./hostlist/`），文件名为 URL 的 SHA256 哈希。重启时优先读取本地缓存，后台再同步远程更新。

## Prometheus 指标

| 指标 | 类型 | 说明 |
|------|------|------|
| `coredns_hostlist_blocked_requests_total` | Counter | 被拦截的请求数（标签：server, zone） |
| `coredns_hostlist_domains_loaded` | Gauge | 当前加载的封锁域名数 |

## 编译

### 1. 克隆 CoreDNS 源码

```bash
git clone https://github.com/coredns/coredns.git coredns
cd coredns
```

### 2. 添加 hostlist 插件

```bash
git clone https://github.com/qist/hostlist.git plugin/hostlist
```

### 3. 注册插件

```bash
grep -q '^hostlist:hostlist' plugin.cfg || sed -i '/^tsig:tsig$/a hostlist:hostlist' plugin.cfg
```

这会在 `tsig:tsig` 之后插入 `hostlist:hostlist`，如果已存在则跳过。

### 4. 生成代码并编译

```bash
go generate
go build -o coredns .
```

### 5. 验证

```bash
./coredns -version
./coredns -plugins | grep hostlist
```

### 使用 Go module 方式添加

如果需要以 module 方式引入（适用于 CoreDNS 自定义构建）：

```bash
# 在 CoreDNS 项目根目录
go mod edit -require github.com/qist/hostlist@latest
go mod edit -replace github.com/qist/hostlist=./plugin/hostlist
go mod tidy
```

然后在 `plugin.cfg` 中使用完整包路径：

```
hostlist:github.com/qist/hostlist
```
## 常见问题

### Q: 规则加载失败怎么办？
A: 插件会使用本地缓存，不会中断 DNS 服务。

### Q: 如何验证规则是否生效？
A: 使用 `dig @127.0.0.1 example.com` 测试，查看日志输出。

### Q: 内存占用过高？
A: 设置 `GOGC=50` 环境变量启动 CoreDNS。