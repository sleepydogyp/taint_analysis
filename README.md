# taint_analysis

目的是检测Android应用获取用户隐私的情况。

把Android app反编译后，解析其smali代码，并实现数据流分析、调用图分析等。

依据FlowDroid的`SourceAndSinks.txt`,生成了本工具的Source和Sinks。

smali的解析使用了github上一个博主的开源代码（暂时找不到原博了），在此基础上做了一些修改，非常感谢~~