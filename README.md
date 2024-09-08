# chrome_password_dumper
导出chrome密码的工具
原理：
1. 获取加密的密钥
读取 Local State 文件：

从用户配置文件目录中读取 Local State 文件。

解析文件内容，提取出加密的密钥。

解密密钥：

使用 Windows 的 CryptUnprotectData 函数解密从 Local State 文件中提取的加密密钥。

2. 获取加密的密码
读取登录数据：

从 Chrome 的登录数据文件（Login Data）中读取加密的密码。

解密密码：

使用 AES-GCM 算法和之前解密的密钥来解密从登录数据文件中提取的加密密码。
