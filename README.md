# SFuzzer

ssj 觉得 SAST 学得行了（膨胀了），打算开始学习 fuzz，并且实现一个手脚齐全的 fuzzer。

## 初步想法

- wrapper —— hook 编译时的命令，在编译结束后先对 .s file 插桩，再执行 as 进行汇编。
- fuzzer —— 先不写 fork server 了，直接跑程序，通过启发式算法更改输入，崩了做记录（先不打印路径了，把输入记下来慢慢用 gdb 调吧）。

至此一个简单的 fuzzer 就完成了。

如果还真 tm 有人看到这个，觉得我哪里说的不对，请 tm 在 issues 怼我，谢谢。
