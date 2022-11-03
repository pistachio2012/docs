## 目的
最近有个项目是在Android4.4的电视上运行Chromium，因此将最新版本的Chromium中某些java源码进行了降级处理。

## c/c++
这部分没有大的修改，主要是去掉一些用到新java api的jni。

## java
这部分修改的比较多，因为target sdk版本和实际运行的sdk一定会有一些差距的，这样就需要做android4.4的兼容调用。

## gn
这部分主要是修改编译时ndk的版本和sdk版本。