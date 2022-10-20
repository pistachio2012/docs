## 起因
NPAPI因为安全性和稳定性的原因已经在最新版本的Chromium上去掉了，但是之前的一些老版本应用还在使用，为了增加应用的迁移能力，因此在不考虑安全的情况下将NPAPI添加到最新版的Chromium上。

## 策略
### 添加到Render进程中
Chromium是多进程架构，正常NPAPI这种plugin是要在单独的进程中运行的，这样可以保证安全性和稳定性。但是只是迁移老应用，因此plugin是已经存在了，不是新开发的，并且其安全性和稳定性已经经过了测试，因此可以在Render进程直接添加NPAI，不必在单独的进程中运行。

### NPAPI原理
NPAPI是在浏览器中添加native代码并且与其进行交互。在liunux上，native代码是以so方式存在，加载so后，为了进行交互，因此定义了一套规则来约定类型和方法，这就是NPAPI。浏览器是通过js与native进行交互，因此NPAPI主要是js引擎和native的交互规则，在chromium上就是通过v8接口来实现NPAPI定义的规则，当然除了NPAPI还定义了一些native获取浏览器资源的接口，如window。

### 实现思路
通过原理可以分析出，主要有两大模块需要做，一是js交互，一是资源交互。其中js交互可以分为两小块，一是类型的转换，一是方法的链接调用。资源交互可以分为两小块，一是数据交换，一是数据处理。

## 行动
### 代码来源和位置
Chromium当然要下最新版本的，NPAPI相关代码可以从WebKit中copy后修改，主要是两个目录，一个是WebCore/plugins，这是NPAPI相关定义和实现，一个是WebCore/bridge，这是与v8进行交互的实现。这两个目录可以copy到最新版本Chromium的third_party/blink/renderer中，但是其具体的修改可以参考老版本的Chromium中NPAPI相关的代码。

### 修改plugin加载
在linux上plugin是在找到特定位置的so后，dlopen加载这个ELF格式的so，这块主要是在PluginPackage中，dlopen后需要通过dlsym获取几个NPAPI定义的接口，并且调用这些接口进行初始化和获取信息，NP_Initialize用于初始化，NP_Shutdown用于关闭plugin，NP_GetMIMEDescription用于获取plugin的MIME，NP_GetValue用于获取plugin的name和description。如果plugin是windows的PE格式，那么在linux上需要自定义loader来加载了，这可以参考wine的loader。

### plugin的初始化
plugin的初始化主要是将接口函数添加到两个struct中，一个是NPNetscapeFuncs，这需要browser赋值，里面都是plugin调用browser的接口，一个是NPPluginFuncs，这是plugin赋值，里面都是browser调用plugin的接口。

### 实现NPNetscapeFuncs中的接口
从接口定义中可以看出，多数比较好实现，比较难的部分有三块，一块是NPStream相关，这需要和Chromium的渲染系统配合好，一块是java相关，这需要调用jvm，一块是js相关，这需要通过bridge和v8进行配合。

### 实现NPPluginFuncs调用
browser会通过调用NPPluginFuncs中的接口传递资源或事件给plugin，比如NPWindow或event等。这需要创建相应的数据，并且在适当的地方调用接口。

### NP类型与browser中的类型转换
NP类型都是c定义的，browser中的类型大部分可以和NP直接转换，但是有些是需要进行转换的，比如NPString和WTF::String之间。

### plugin与v8之间的交互——bridge
plugin可以通过注册js接口和浏览器进行交互，这部分是在bridge中实现的。

#### NPClass和NPObject
这是NPAPI定义的类型，分别是plugin的类型和对象，类型用于定义接口，对象用于创建和调用。因此这部分主要就是将这两个类型Wrapper成与v8可以相互调用的粘合剂。尤其是NPObject，这个是与v8中的Object对应的，js执行时的调用会解析到NPObject的Wrapper，然后调用到plugin中。

#### 其他类型
其他类型都是辅助作用，比如Filed,Method,Class,Instance,Array,RootObject等，这些都是注册到v8中，以便于将v8中的调用转换成plugin中的调用。

#### 类型转换
v8中的基础类型和NP类型是需要转换的，其中大部分都是直接转换，如整数，还有一些需要转换函数，如果字符串。

## 结果
本文是通过看源码和对NPAPI的实现理解写成，没有深入到实现细节，但是实现迁移NPAPI是没有问题的。
### 局限性
- plugin的主要是linux上的，即为ELF格式
- 与v8交互主要参考的源码，和JSC的实现
- 除了bridge部分，其他的接口都会有些不确定性，因为这和plugin中的实现有关


