 GenericInjector
=============================
GenericInjector是一个用于简化注入器编写的通用Win32程序注入器模板，作者的目标是通过使用它来快速开发注入器并减少不必要的错误。

部分源码及设计思想参考于 acaly 的工程 GSInjector ，在此向其致谢。

这个工程使用GPLv3协议开源，意在促进互相学习。工程本身还极不完善，作者不推荐将其或其一部分用于大型工程。

目前开发完成的功能有：

* 分析已加载的Win32程序的输入表，并可以进行快速注入。

* 分析对象的虚表并进行注入（仅在Visual Studio 2015生成的程序上验证通过，其他编译器生成的程序未进行测试）。

* 提供一定程度上的类型安全的注入。

工程使用Visual Studio 2015进行编译，其他编译器未进行测试。

对于工程的疑问可以在百度贴吧上 @jxhzq1996 或者加 QQ 794424922 进行交流。
