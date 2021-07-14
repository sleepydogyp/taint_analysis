# taint_analysis

- 目的是检测Android应用获取用户隐私的情况。

- 依据FlowDroid的`SourceAndSinks.txt`,生成了本工具的Source和Sinks。

- smali文件的解析使用了github上一个博主的开源项目[PATDroid](https://github.com/mingyuan-xia/PATDroid)，非常感谢~~

- 把Android app反编译后，使用PATDroid解析smali代码格式的功能，在此基础上做了一些修改，实现数据流分析、调用图分析等，最终实现污点分析的效果。

- 功能还不完善，目前还在测试中，继续加油

