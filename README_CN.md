# 本fork改动：内置 eMudhra 受损中间 CA

本 Fork 将 ProxyPin 的**内置签发 CA 替换为 8 张受损的 eMudhra 中间 CA**（用户可从这 8 张中任选其一），
让 HTTPS 中间人（MITM）在**未 Root、且尚未修复该事件**的设备上**直接抓包**——无需把 CA 装进系统信任库，也无需 Magisk/Xposed。

**如何选择**：新增的「签发 CA」入口：
- 桌面：HTTPS 菜单 → 签发 CA → 签发机构 / 信任路径
- 移动端：HTTPS 设置 → 签发 CA

可选项为 8 张 eMudhra 中间 CA（DV/OV/EV/CS × G3B/G3C）与内置 ProxyPin 根，以及两条信任路径（emSign / Sectigo AAA）。
列表中 TLS 类显示 ✓（链到被广泛信任的锚点），CS 类与本地根显示 ⚠（受限/需手动安装）。

**为什么无需 Root**：这 8 张中间 CA 的私钥是公开的（secp384r1，标量 d 仅 1 字节），ProxyPin 用它们现场签发域名叶子证书；
叶子沿 `中间 CA → emSign Root TLS/CS CA - G3 → emSign ECC Root CA - G3`（或 Sectigo `AAA Certificate Services`）
链到设备**系统自带**的信任锚点，因此凭系统级信任即可通过校验。

**限制**：仅对仍未移除这 8 张中间 CA 信任的“未修复”设备有效；已被 Mozilla/Apple/Chrome/Microsoft 撤销信任
（2026‑10‑17~20）的系统与浏览器会提示证书错误。CS 类（07/08）的 emSign 路径仅链到 Microsoft 信任的根。

参考：CVE-2026-111943 · 披露站 https://emudhra.we-have-a-problem.com/

## Linux 打包

- **Debian/Ubuntu**：预构建的 `.deb` 发布在本 fork 的 [Releases](https://github.com/azhuquq/proxypin-with-emudhra-ca/releases)（`sudo dpkg -i` 安装）。包安装到 `/opt/proxypin-emudhra`，并使用独立的
  application id（`com.network.proxy.emudhra`），可与原版 ProxyPin 的 deb **共存安装**。自行打包：先
  `flutter build linux --release`，再运行 `linux/build_fork_deb.sh`（无 dpkg 的环境会自动改用 `ar`/`tar` 组装）。
- **Arch Linux**（未发布 AUR）：用 `packaging/arch/` 下的 `PKGBUILD`，`makepkg -si` 构建安装；`proxypin-emudhra-git`
  包跟踪本 fork 的 `main` 分支（版本号由 `git describe` 推导），共存布局与 deb 相同。构建依赖 `flutter` 与 `rustup`——
  cargokit 会在构建时下载 stable Rust toolchain，请保持联网。

以下为原文

---

# ProxyPin

[English](README.md) | 中文
## 开源免费抓包工具，支持Windows、Mac、Android、IOS、Linux 全平台系统

您可以使用它来拦截、检查和重写HTTP（S）流量，支持Flutter应用抓包，ProxyPin基于Flutter开发，UI美观易用。

## 核心特性

* 手机扫码连接: 不用手动配置Wifi代理，包括配置同步。所有终端都可以互相扫码连接转发流量。
* 域名过滤: 只拦截您所需要的流量，不拦截其他流量，避免干扰其他应用。
* 搜索：根据关键词响应类型多种条件搜索请求
* 脚本: 支持编写JavaScript脚本来处理请求或响应。
* 请求重写: 支持重定向，支持替换请求或响应报文，也可以根据增则修改请求或或响应。
* 请求映射: 不请求远程服务，使用本地配置或脚本进行响应
* 请求解密: 配置AES解密密钥，自动解密HTTP消息体
* 请求屏蔽: 支持根据URL屏蔽请求，不让请求发送到服务器。
* 历史记录：自动保存抓包的流量数据，方便回溯查看。支持HAR格式导出与导入。
* 其他：收藏、工具箱、常用编码工具、以及二维码、正则等

**Mac首次打开会提示不受信任开发者，需要到系统偏好设置-安全性与隐私-允许任何来源。**

## 赞助 

如果您觉得ProxyPin对您有帮助，欢迎通过以下方式支持我们，帮助项目长期发展：

* [爱发电赞助](https://afdian.com/a/proxypin)
* [Buy Me A Coffee](https://buymeacoffee.com/proxypin)
* 提交反馈和建议，帮助我们改进
* 为项目贡献代码或文档

**您的支持将用于项目的维护、功能开发和用户体验优化，非常感谢！**    

## 下载地址

国内下载： https://gitee.com/wanghongenpin/proxypin/releases

iOS App Store： https://apps.apple.com/app/proxypin/id6450932949      

Android Google Play：https://play.google.com/store/apps/details?id=com.network.proxy

TG: https://t.me/proxypin_tg

**接下来会持续完善功能和体验，UI优化。**

<img alt="image"  width="580px" height="420px"  src="https://github.com/user-attachments/assets/80f30d64-f2b5-473c-98f5-bae50b309278">.<img alt="image"  height="500px" src="https://github.com/user-attachments/assets/3c5572b0-a9e5-497c-8b42-f935e836c164">

