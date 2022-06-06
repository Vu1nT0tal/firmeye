# firmeye - IoT固件漏洞挖掘工具

firmeye 是一个 IDA 插件，基于敏感函数参数回溯来辅助漏洞挖掘。我们知道，在固件漏洞挖掘中，从敏感/危险函数出发，寻找其参数来源，是一种很有效的漏洞挖掘方法，但程序中调用敏感函数的地方非常多，人工分析耗时费力，通过该插件，可以帮助排除大部分的安全调用，从而提高效率。

- 漏洞类型支持：缓冲区溢出、命令执行、格式化字符串
- 架构支持：ARM

分享：[slides](./firmeye.pdf)

## 安装

该插件运行环境要求 IDA Pro 7.5，Python3。

1. 下载本项目：`https://github.com/firmianay/firmeye.git`。
2. 安装依赖：`pip install -r requirements.txt`。
3. 将 `firmeye` 和 `firmeye.py` 复制到 IDA Pro 插件目录下，例如 `C:\Program Files\IDA Pro 7.5\plugins`。
4. 打开 IDA Pro 并加载待分析固件程序。
5. `Ctrl+F1` 查看插件使用帮助。热键：
    - `Ctrl+Shift+s`：主菜单
    - `Ctrl+Shift+d`：启动/禁用调试钩子
    - `Ctrl+Shift+c`：扫描代码模式（TODO）
    - `Ctrl+Shift+x`：逆向辅助工具
    - `Ctrl+Shift+q`：功能测试

## 使用方法

### 静态分析功能

敏感函数被分为 5 类：printf、strcpy、memcpy、scanf、system。分别对应各自的漏洞类型和检测规则。

### 动态调试功能

对静态分析得到的可疑地址下断点，并在调试时动态处理断点事件，获得参数、返回值等上下文信息。

## 命令行工具

利用 [idahunt](idahttps://github.com/nccgroup/idahunt) 可以让插件自动化批量运行，使用方法如下：

```sh
$ python3 idahunt.py --inputdir C:\xxxx --analyse --filter "names.py -a 32 -v"                      # 生成IDB
$ python3 idahunt.py --inputdir C:\xxxx --cleanup                                                   # 清理临时文件
$ python3 idahunt.py --inputdir C:\xxxx --filter "names.py -a 32 -v" --scripts "firmeye_cli.py"     # 运行脚本
```

## 改进方向

该插件目前还非常不完善，下面是一些改进方向，欢迎讨论和 PR。

- 完善参数回溯逻辑，支持更复杂的指令语义识别
- 支持函数间分析
- 完善漏洞判断逻辑，降低误报率
- 加入动态污点分析作为辅助
- 支持更多体系架构，如 x86、MIPS 等

## 关注我们

[VulnTotal安全团队](https://github.com/VulnTotal-Team)成立于2022年。致力于分享高质量原创文章和开源工具，包括Web安全、移动安全、物联网/汽车安全、代码审计、网络攻防等，欢迎[关注或加入我们](https://github.com/VulnTotal-Team/.github/blob/main/README.md)！

GNU General Public License v3.0

[![Stargazers over time](https://starchart.cc/VulnTotal-Team/firmeye.svg)](https://starchart.cc/VulnTotal-Team/firmeye)
