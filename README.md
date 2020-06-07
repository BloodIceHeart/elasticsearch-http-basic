## 替代方法
请参见[Search Guard] https://docs.search-guard.com/

## ElasticSearch的HTTP基本/ IP身份验证
1、配置简单  
2、有白名单配置，白名单ip列表用户无需验证可直接访问，白名单外用户需用户名密码  
3、由于白名单无法控制通过域名的访问，如果要通过域名访问ES必须要通过用户名和密码来访问  
4、添加Web登录页面，默认跳转_plugin/head插件页面  
5、(后续完成)添加登录主页面及参数配置页面  
参考https://github.com/Asquera/elasticsearch-http-basic开发的elasticsearch2.2.1版本  

## 对应elasticsearch版本

|     Http Basic Plugin       | elasticsearch                |
|-----------------------------|------------------------------|
| v2.2.1(master)              | 2.2.1                        |

## 安装

从 https://github.com/BloodIceHeart/elasticsearch-http-basic 下载对应版本的安装至 `plugins/http-basic`.

## 配置

插件安装完成后，即可在$ES/config/elasticsearch.yml配置

|     Setting key                   |  默认值                      | 备注                                                        | 
|-----------------------------------|------------------------------|------------------------------------------------------------|
| `http.basic.enabled`              | true                         | 开启/关闭 HTTP基本/ IP身份验证                              | 
| `http.basic.user`                 | "admin"                      |                                                            | 
| `http.basic.password`             | "admin123"                   |                                                            | 
| `http.basic.ipwhitelist`          | ["localhost", "127.0.0.1"]   | 设置 false 禁用白名单                                       | 
| `http.basic.trusted_proxy_chains` | []                           | 设置一组受信任的代理ips链                                   | 
| `http.basic.log`                  | true                         | 启用插件日志记录到ES日志。 未经身份验证的请求始终被记录           | 
| `http.basic.xforward`             | ""                           | 没搞懂这个参数！！！                                        | 
| `http.basic.login`                | true                         | 启用web登录页面                                             | 
| `http.basic.token.name`           | "sinosoftSSO"                | 登录令牌参数名（支持第三方验证令牌）                          | 
| `http.basic.token.uri`            | ""                           | 第三方令牌验证地址 uri?‘token.name’=xxx(返回true or false)   | 
| `http.basic.token.imeout`         | 1800000                      | 令牌失效时间                                                | 
| `http.basic.token.size`           | 20                           | 令牌缓存数量（超过此数量会触发清理失效令牌）                  | 

请注意，密码以纯文本存储。

## Http基本认证
|         参数配置               |         用途                              |
|-------------------------------|-------------------------------------------|
| `http.basic.enabled: true`    | 开启/关闭 HTTP基本/ IP身份验证             |
| `http.basic.login: true`      | 启用web登录页面                            |
| `http.basic.login: false`     | 启用 WWW-Authenticate 验证                |

## 基于IP的身份验证
|         参数配置                       |         用途               |
|---------------------------------------|----------------------------|
| `http.basic.ipwhitelist: []`          | 白名单设置                  |
| `discovery.zen.ping.unicast.hosts:[]` |集群配置会自动加入白名单     |

