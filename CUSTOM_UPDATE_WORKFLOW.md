# Custom Update Workflow

本仓库当前采用两条本地分支分工：

- `custom-portal-gpio-zh`
  用于长期维护源码改动，例如中文 AP 页面、GPIO 运行时配置等
- `release-20260525`
  用于保存当前生成的固件交付物

分支名都可以自定义，后续也可以改名。

## 作者更新后怎么同步

先切回源码维护分支：

```bash
git checkout custom-portal-gpio-zh
```

拉取作者最新代码：

```bash
git fetch origin
```

同步作者更新，二选一：

```bash
git merge origin/main
```

或者：

```bash
git rebase origin/main
```

如果有冲突，处理完冲突后重新编译验证。

## 什么时候重新做发布包

当以下任一情况发生后，建议重新生成发布固件：

- 作者更新了源码
- 你修改了页面、GPIO、板级逻辑
- 你切换了目标板型或分区方案

常用构建命令：

```bash
/Users/han/.platformio/penv/bin/pio run -e squeezeamp -e esparagus-audio-brick
/Users/han/.platformio/penv/bin/pio run -e squeezeamp -e esparagus-audio-brick -t buildfs
```

## 重新整理 release 的建议流程

如果要重新发布固件，建议新建一个新的发布分支或 tag，而不是把二进制文件直接塞进源码维护分支。

示例：

```bash
git checkout custom-portal-gpio-zh
git checkout -b release-YYYYMMDD
```

然后把新的 `release/` 内容提交到这个发布分支。

## 可选改名

如果你想改源码维护分支名：

```bash
git branch -m 新分支名
```

如果你想改发布分支名：

```bash
git branch -m 旧发布分支名 新发布分支名
```
