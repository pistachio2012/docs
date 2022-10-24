## 删除test相关文件
### 通过文件名查找并删除
fdfind -E"*hit_test*" test | xargs rm -rf
这个命令能够删除文件名中带test的文件，除了hit_test，主要包括unittest,browsertest,Test等。
### testing目录
有些文件如果删除，那么需要修改的源文件会很多，因此这些文件要保留，但是需要做些空白修改。
如testing目录下的test.gni，fuzzer_test.gni，gtest_prod.h等

## 修改gn文件
删除test文件后，在gn文件中依然会有这些文件的引用，在gen时会报错，找不到文件。
### target中含有test
在引用test相关文件的target都会在名字中包含test，因此只需修改target，将其写空就不会用到test文件的引用了，如
```
template("static_library") {
  if (filter_exclude([ target_name ], [ "*test*", "*mock*" ]) == []) {
    not_needed(invoker, "*", TESTONLY_AND_VISIBILITY)
    not_needed(invoker, TESTONLY_AND_VISIBILITY)
    group(target_name) {}
  } else {
    static_library(target_name) {
      forward_variables_from(invoker, "*", TESTONLY_AND_VISIBILITY)
      forward_variables_from(invoker, TESTONLY_AND_VISIBILITY)
    }
  }
}
```
但是会有几个target改不了，比如copy，这比较少可以在对应的gn文件中直接改。
### 修改mojo文件中的test
mojo文件中会有test相关的接口，这些接口有的会用到相应的test.mojo文件，因此要注释这些文件中对test.mojo文件的引用，并且将对应的test接口注释就可以了。注释方法也很简单，和c注释是一样的。
### 修改python文件
Chromium中有些文件是通过python生成的，比如idl文件，在生成文件中会有test相关文件引用和调用，也会在生成源码文件同时生成其对应的test文件，因此只需修改python文件中test相关的引用和生成就可以了。
### 修改tmpl文件
tmpl文件是生成源码用的模板文件，如果在模板文件中包含了test相关的引用和调用，那么就会在生成文件有test代码，因此需要注释tmpl文件中test相关的引用和调用。
