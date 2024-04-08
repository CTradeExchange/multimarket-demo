# multimarket-demo

## 示例
```
String pk = "XXXX"; // 替换公钥

/**
* {\"name\":\"XXXX\"} 是原始的请求参数
*/
String body = encrypt("{\"name\":\"XXXX\"}", pk);

// 输出加密后的数据
System.out.printf(body);

```
