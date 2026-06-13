# nginx-gmssl

`nginx-gmssl` 是基于 Nginx 1.30.2 的 GmSSL 适配版本。这个项目将 Nginx 原有的 OpenSSL 后端替换为 GmSSL TLS 接口，使 HTTP SSL 模块可以使用国密 TLS 能力提供 HTTPS 服务。

当前实现面向服务端 HTTPS 场景，支持把一个 `server` 配置为 TLCP、TLS 1.2 或 TLS 1.3 三种协议之一。由于 GmSSL 当前服务端接口尚不支持在同一个连接中同时协商 TLCP、TLS 1.2、TLS 1.3，本项目要求每个 `server` 的 `ssl_protocols` 只启用一个协议。

原始 Nginx 项目说明保留在 [README](README)。

## 支持的协议和套件

当前 GmSSL 后端默认配置如下：

| Nginx 配置 | GmSSL 协议 | 默认套件 |
| --- | --- | --- |
| `ssl_protocols TLCP;` | TLCP | `TLS_ECDHE_SM4_CBC_SM3`, `TLS_ECC_SM4_CBC_SM3` |
| `ssl_protocols TLSv1.2;` | TLS 1.2 | `TLS_ECDHE_SM4_CBC_SM3` |
| `ssl_protocols TLSv1.3;` | TLS 1.3 | `TLS_SM4_GCM_SM3` |

曲线默认使用 `sm2p256v1`，签名算法默认使用 `sm2sig_sm3`。当前后端主要覆盖静态文件服务和 HTTP 反向代理入口的 HTTPS 连接；SNI、ALPN、客户端证书验证、会话恢复、OCSP Stapling 等 OpenSSL 生态中的高级能力尚未完整映射到 GmSSL。

## 编译

先安装或构建 GmSSL，并确保头文件和动态库可被 Nginx 找到。例如 GmSSL 安装到 `/usr/local`：

```sh
./configure --with-http_ssl_module --with-gmssl=/usr/local
make -j
```

如果运行时系统找不到 `libgmssl`，可以在配置时增加 rpath：

```sh
./configure --with-http_ssl_module --with-gmssl=/usr/local \
    --with-ld-opt="-Wl,-rpath,/usr/local/lib"
make -j
```

启动时会检查编译期 `GMSSL_VERSION_STR` 和运行时 `gmssl_version_str()` 是否一致。如果 Nginx 链接到的 GmSSL 动态库与编译时使用的头文件版本不一致，Nginx 会报错并停止启动。

## 安全注意事项

- 请使用可信来源构建或安装 GmSSL，并保证运行时加载的 `libgmssl` 与编译时头文件版本一致。
- TLCP 需要签名证书和加密证书两套 SM2 证书/私钥。TLS 1.2 和 TLS 1.3 示例使用 SM2 签名证书链和对应私钥。
- 私钥建议使用口令加密，并通过 `ssl_password_file` 指定口令文件。生产环境中应限制证书、私钥、口令文件权限。
- 当前后端不支持在同一个 `server` 中同时启用多个 TLS/TLCP 协议版本；请按端口或虚拟主机拆分。
- 本项目仍属于适配实现，部署到生产环境前应结合业务场景进行互操作性、错误处理、日志和安全测试。

## SSL 和证书配置

TLS 1.2 示例：

```nginx
server {
    listen 8443 ssl;
    server_name localhost;

    ssl_protocols TLSv1.2;
    ssl_certificate /path/to/sm2certs.pem;
    ssl_certificate_key /path/to/sm2signkey.pem;
    ssl_password_file /path/to/pass.txt;

    root /path/to/html;
}
```

TLS 1.3 示例：

```nginx
server {
    listen 8444 ssl;
    server_name localhost;

    ssl_protocols TLSv1.3;
    ssl_certificate /path/to/sm2certs.pem;
    ssl_certificate_key /path/to/sm2signkey.pem;
    ssl_password_file /path/to/pass.txt;

    root /path/to/html;
}
```

TLCP 示例：

```nginx
server {
    listen 8445 ssl;
    server_name localhost;

    ssl_protocols TLCP;
    ssl_certificate /path/to/double_certs.pem;
    ssl_certificate_key /path/to/double_keys.pem;
    ssl_password_file /path/to/pass.txt;

    root /path/to/html;
}
```

TLCP 的 `double_certs.pem` 通常按签名证书、加密证书、CA 证书链顺序拼接；`double_keys.pem` 通常按签名私钥、加密私钥顺序拼接，并使用相同口令。

反向代理入口也可以使用 GmSSL HTTPS：

```nginx
server {
    listen 8446 ssl;
    server_name localhost;

    ssl_protocols TLSv1.2;
    ssl_certificate /path/to/sm2certs.pem;
    ssl_certificate_key /path/to/sm2signkey.pem;
    ssl_password_file /path/to/pass.txt;

    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

仓库中的 `gmssl-tests/` 提供了本地测试配置：

- `gmssl-tests/tls12.conf`
- `gmssl-tests/tls13.conf`
- `gmssl-tests/tlcp.conf`
- `gmssl-tests/proxy_tls12.conf`

这些配置包含本机路径，换到其他机器时需要按实际 GmSSL 构建目录和仓库路径调整证书路径、口令文件路径和 `root` 路径。

## 使用 gmssl 命令行测试

启动 TLS 1.2 测试服务：

```sh
objs/nginx -p "$PWD/gmssl-tests/runtime" -c "$PWD/gmssl-tests/tls12.conf"
```

使用 GmSSL TLS 1.2 客户端访问：

```sh
printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
gmssl tls12_client \
    -host 127.0.0.1 -port 8443 \
    -cacert /path/to/sm2rootcacert.pem \
    -cipher_suite TLS_ECDHE_SM4_CBC_SM3 \
    -supported_group sm2p256v1 \
    -sig_alg sm2sig_sm3
```

TLS 1.3：

```sh
printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
gmssl tls13_client \
    -host 127.0.0.1 -port 8444 \
    -cacert /path/to/sm2rootcacert.pem \
    -cipher_suite TLS_SM4_GCM_SM3 \
    -supported_group sm2p256v1 \
    -sig_alg sm2sig_sm3
```

TLCP：

```sh
gmssl tlcp_client \
    -host 127.0.0.1 -port 8445 \
    -cacert gmssl-tests/tlcp-certs/rootcacert.pem \
    -cipher_suite TLS_ECC_SM4_CBC_SM3 \
    -get /
```

反向代理测试：

```sh
objs/nginx -p "$PWD/gmssl-tests/runtime" -c "$PWD/gmssl-tests/proxy_tls12.conf"

printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
gmssl tls12_client \
    -host 127.0.0.1 -port 8446 \
    -cacert /path/to/sm2rootcacert.pem \
    -cipher_suite TLS_ECDHE_SM4_CBC_SM3 \
    -supported_group sm2p256v1 \
    -sig_alg sm2sig_sm3
```

预期可以看到 HTTP 响应头和测试页面内容。

## 许可证

本项目基于 Nginx 源码，遵循原 Nginx 许可证。GmSSL 遵循其自身项目许可证。
