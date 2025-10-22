Frida
=================

#### Frida安装

```bash
 pip install frida-tools
```

#### Frida命令

```bash
  # 查看版本
  frida --version
  # 查看进程包名
  frida-ps -Ua
  # 启动脚本 进程ID 脚本文件
  frida -U -p 21847 -l script.js
  # spawn模式启动
  frida -U -f com.immomo.momo -l script.js
```

#### Shell命令

```bash
  # 查看系统架构
  getprop ro.product.cpu.abi
```

#### [Frida Server](https://github.com/frida/frida/releases)

> frida-server-16.5.9-android-x86_64.xz
根据架构下载对应版本 解压后重命名sudo

#### 连接模拟器(mumu)
```bash
  adb connect 127.0.0.1:7555
```

#### 注入sudo

```bash
  # 获取超级用户
  su
  # 最高权限
  chmod 777 sudo
  # 启动
  ./sudo
```
#### 其他命令

```bash
  # 执行脚本
  python apply.py http
```

#### 日志命令

```bash
  # 执行脚本
  adb logcat --pid=5554
```

#### 发送参数

```json
{
   "momoid": "******",
   "remoteId": "******",
   "content": "979025201"
}
```

> **注意**: apk放在test/resources下


#### objection使用

```bash
pip install objection

objection -g MOMO陌陌 explore

android hooking watch class pkg

# 构造 .$init
android hooking watch class_method pkg.d --dump-args --dump-return --dump-backtrace
```

#### UI审查

###### 安装appium服务端

```bash
npm install -g appium
```
###### github下载这两款软件
###### 安装appium-server GUI 直接启动
###### 安装appium-inspector GUI 直接启动
###### 启动appium


```bash
appium --allow-cors --port 4725
```
###### appium-inspector需要填写参数
###### Remote Host 本机IP
###### Remote Port 指定端口
###### Remote Path /
###### 连接MUMU JSON配置

```json
{
  "platformName": "Android",
  "appium:platformVersion": "12",
  "appium:deviceName": "MuMu",
  "appium:appPackage": "com.immomo.momo",
  "appium:appActivity": "com.immomo.momo/.android.activity.WelcomeActivity",
  "appium:automationName": "UiAutomator2",
  "appium:udid": "127.0.0.1:7555"
}
```

###### 安装uiautomator2

```bash
appium driver install uiautomator2
```
###### Start Session 启动

###### 魔改frida 过检测

> florida-server-16.6.6-android-arm64.gz
