## 目的
Chromium源码有多层，chrome，webview层实际上都是调用的content层，因此直接在content层对外提供自定义WebView接口，就能即简单又可控地提供浏览器功能。

## 修改Shell和ShellManager
content层有一个比较薄的用于测试的shell封装，直接修改这层封装就可以将浏览器改成想要的样子。在Android上对外是java接口，因此shell封装有java和jni两部分实现，修改也分这两部分，java主要是改界面，将界面修改成需要的模样，比如网页全屏，jni主要是增加需要的接口，用于配置浏览器。

## 增加WebView接口
增加java的WebView类，用于对外提供接口，主要是初始化，配置和加载接口等，WebView实现主要是调用Shell和ShellManager。

## 打包成aar
这个主要是so和class打包后能够更方便地提供给第三方进行集成。这部分主要是修改gn文件，添加一个target，依赖so和class。