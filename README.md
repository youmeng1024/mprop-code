某次看到mprop这个小工具，但是无奈作者并没有公布源码。于是萌生了自己动手写一个的念头。当然，自己并没有相关只是，所以也就是等于顺便学习了一波。https://bbs.pediy.com/thread-215311.htm  根据作者的字里行间，进程注入，修改内存这几个关键字眼，以此为思路，我查找了相关的资料文章，并进行了简单的代码编写测试。在ubuntu上使用ptrace正常，然后遇到了gcc编译c程序到android上的各种问题，详细查看下面的专门笔记。
最后，自己的思路大概是，使用ptrace来attach到安卓里面的init进程

  prop_info* pi = (prop_info*) __system_property_find(name.c_str());
    if (pi != nullptr) {
        // ro.* properties are actually "write-once".
        if (android::base::StartsWith(name, "ro.")) {
            LOG(ERROR) << "property_set(\"" << name << "\", \"" << value << "\") failed: "
                       << "property already set";
            return PROP_ERROR_READ_ONLY_PROPERTY;
        }
        __system_property_update(pi, value.c_str(), valuelen);
    } else {
        int rc = __system_property_add(name.c_str(), name.size(), value.c_str(), valuelen);
        if (rc < 0) {
            LOG(ERROR) << "property_set(\"" << name << "\", \"" << value << "\") failed: "
                       << "__system_property_add failed";
            return PROP_ERROR_SET_FAILED;
        }
        
    
关键就是判断ro那行代码。一开始是打算将整个判断代码nop掉。。但后面发现有点问题，一个是整个代码nop量有点多，另一个主要问题是我找不到这行代码在进程中的位置。。主要是不知道为什么，init进程使用readelf和objdump两个工具都没办法找到这些函数名，但他们又确实不是使用动态链接库。因此暂时怀疑是因为init进程使用了静态编译才这样。。也有可能自己相关知识不够扎实。。另外想到一个以后可以实验的办法（可以使用c层面的hook来根据strcmp找到函数返回地址确定。）。。最后无奈下，想了个取巧的办法，查找判断中“ro.”的字串位置更改掉，这样子判断无法set的时候就不是ro.了。算取巧。。按照仅剩不多的记忆，做点笔记。。
