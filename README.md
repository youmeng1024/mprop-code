## 能干啥
android设备在root环境下，修改ro属性的值。  
原来版本是在android 6搞的，没针对64位机子，现在这类机子比较多。目前找的几个mprop想要改ro.debuggable都改不了，只能自己把原来的更一把了

## 注意
root环境下使用！！root环境下使用！！root环境下使用！！  

selinux要关闭！！selinux要关闭！！selinux要关闭！！  

## 使用
```
adb push mprop2 /data/local/tmp
(root) chmod 755 /data/local/tmp/mprop2
(root) /data/local/tmp/mprop2 $pid --on|--off
```
主要针对的是init进程，遇到过进程号不是1的init进程，因此，还是使用时查一把传参吧  
原理和原来旧版一样，init进程的内存中找到ro.所在，直接替换掉该字符串。  
为了确保效果，现在把进程的所有内存一点点便利一遍，所以会更花时间，长达几十秒  
--on 打开效果，执行完毕后使用setprop｜getprop去确定是否有效  
--off 改完了最好再跑一遍把对init的操作效果改回来。毕竟是把内存里的对应字符串篡改了，不能保证其他代码会不会用到被篡改的地方，保险起见  

## 适用范围
emmm.....手头只有init进程跑的是64位的，，只能说确保自己能用，，其他的情况没条件测，代码放上去了，遇到没效果的可以针对性的改一改自己编一把。不知道我这  原版思路的，可以瞄一眼old_version/README.md 

## 声明
仅供学习参考，概不承担任何后果

## 还想说啥
emmm.....希望对你有所帮助

## 后日谈
啊啊啊,发现vivo的init进程,,连个libc库都没加载..根本没法调用dlopen等方法..处理思路是,程序自己先加载一下libc等库,然后读取dlopen等方法,把整个方法的代码块复制;在目标进程找到一个可写可执行的内存,把内容保存一下,然后把复制的代码块写入,pc指针移过去..执行完毕后恢复现场..
