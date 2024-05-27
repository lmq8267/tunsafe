预编译二进制文件

 TunSafe 1.5-rc2 及以上版本才支持TCP

 配置文件作如下修改：
 ```bash
[Interface]
ListenPortTCP=1234


[Peer]
Endpoint=tcp://5.5.5.5:1234
```
