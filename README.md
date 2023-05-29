
### ebpf


#### support

* eBPF 在 Linux 3.18 版本以后引入，并不代表只能在内核 3.18+ 版本上运行，低版本的内核升级到最新也可以使用 eBPF 能力，只是可能部分功能受限，比如我测试在CentOS7 3.10.940 以上都可以受限使用部分eBPF功能，低版本CentOS7 可以yum升级内核，重启支持部分eBPF 功能。



#### EBPF map type


```bash

BPF_MAP_TYPE_HASH：哈希表
BPF_MAP_TYPE_ARRAY：数组映射，已针对快速查找速度进行了优化，通常用于计数器
BPF_MAP_TYPE_PROG_ARRAY：对应eBPF程序的文件描述符数组；用于实现跳转表和子程序以处理特定的数据包协议
BPF_MAP_TYPE_PERCPU_ARRAY：每个CPU的阵列，用于实现延迟的直方图
BPF_MAP_TYPE_PERF_EVENT_ARRAY：存储指向struct perf_event的指针，用于读取和存储perf事件计数器
BPF_MAP_TYPE_CGROUP_ARRAY：存储指向控制组的指针
BPF_MAP_TYPE_PERCPU_HASH：每个CPU的哈希表
BPF_MAP_TYPE_LRU_HASH：仅保留最近使用项目的哈希表
BPF_MAP_TYPE_LRU_PERCPU_HASH：每个CPU的哈希表，仅保留最近使用的项目
BPF_MAP_TYPE_LPM_TRIE：最长前缀匹配树，适用于将IP地址匹配到某个范围
BPF_MAP_TYPE_STACK_TRACE：存储堆栈跟踪
BPF_MAP_TYPE_ARRAY_OF_MAPS：地图中地图数据结构
BPF_MAP_TYPE_HASH_OF_MAPS：地图中地图数据结构
BPF_MAP_TYPE_DEVICE_MAP：用于存储和查找网络设备引用
BPF_MAP_TYPE_SOCKET_MAP：存储和查找套接字，并允许使用BPF辅助函数进行套接字重定向

```


* 可以使用bpf_map_lookup_elem（）和 bpf_map_update_elem（）函数从eBPF或用户空间程序访问所有Map. 使用 man bpf 查看 bpf 系统调用，int bpf(int cmd, union bpf_attr *attr, unsigned int size) 第1个参数cmd，如下
```bash
BPF_MAP_CREATE： 创建一个 map，并返回一个 fd，指向这个 map，这个 map 在 bpf 是非常重要的数据结构，用于 bpf 程序在内核态和用户态之间相互通信。
BPF_MAP_LOOKUP_ELEM： 在给定一个 map 中查询一个元素，并返回其值
BPF_MAP_UPDATE_ELEM： 在给定的 map 中创建或更新一个元素(关于 key/value 的键值对)
BPF_MAP_DELETE_ELEM： 在给定的 map 中删除一个元素(关于 key/value 的键值对)
BPF_MAP_GET_NEXT_KEY： 在一个特定的 map 中根据 key 值查找到一个元素，并返回这个 key 对应的下一个元素
BPF_PROG_LOAD： 验证并加载一个 bpf 程序。并返回与这个程序关联的 fd。
```

* bpf_attr,第 2 个参数,该参数的类型取决于 cmd 参数的值，本文只分析 cmd=BPF_PROG_LOAD 这种情况，其中 prog_type 指定了 bpf 程序类型，eBPF 程序支持 attach 到不同的 event 上，比如 Kprobe，UProbe，tracepoint，Network packets，perf event 等。

```bash

内核支持的当前eBPF程序类型集为：
BPF_PROG_TYPE_SOCKET_FILTER：网络数据包过滤器
BPF_PROG_TYPE_KPROBE：确定是否应触发kprobe
BPF_PROG_TYPE_SCHED_CLS：网络流量控制分类器
BPF_PROG_TYPE_SCHED_ACT：网络流量控制操作
BPF_PROG_TYPE_TRACEPOINT：确定是否应触发跟踪点
BPF_PROG_TYPE_XDP：从设备驱动程序接收路径运行的网络数据包过滤器
BPF_PROG_TYPE_PERF_EVENT：确定是否触发perf事件处理程序
BPF_PROG_TYPE_CGROUP_SKB：用于cgroups的网络数据包过滤器
BPF_PROG_TYPE_CGROUP_SOCK：用于cgroups的网络数据包过滤器，允许修改socket选项
BPF_PROG_TYPE_LWT_ *：用于隧道的网络数据包过滤器
BPF_PROG_TYPE_SOCK_OPS：用于设置socket参数的程序
BPF_PROG_TYPE_SK_SKB：网络数据包过滤器，用于在socket之间转发数据包
BPF_PROG_CGROUP_DEVICE：确定是否允许设备(device)操作

```


* 比如,cmd=BPF_PROG_LOAD 使用，bpf_attr 字段如下：

```cgo
struct {    /* Used by BPF_PROG_LOAD */
    __u32   prog_type;  //设置为 `BPF_PROG_TYPE_KPROBE`，表示是通过 kprobe 注入到内核函数。
    __u32   insn_cnt;
    __aligned_u64 insns;      /* 'const struct bpf_insn *' */
    __aligned_u64 license;    // 指定 license
    __u32   log_level;  /* verbosity level of verifier */
    __u32   log_size;   /* size of user buffer */
    __aligned_u64 log_buf;    // 用户buff

    __u32   kern_version;
    /* checked when prog_type=kprobe
    (since Linux 4.1) */
};
```


* size：第三个参数
表示上述 bpf_attr 字节大小。
当加载 bpf 程序时，BPF_PROG_LOAD 表示的是加载具体 bpf 指令，对应 SEC宏 下面的函数代码段。
每条指令的操作码由5部分组成：

```cgo

    struct bpf_insn {
            __u8    code;           /* opcode(操作码) */
            __u8    dst_reg:4;      /* dest register(目标寄存器) */
            __u8    src_reg:4;      /* source register (源寄存器)*/
            __s16   off;            /* signed offset(偏移)*/
            __s32   imm;            /* signed immediate constant(立即数) */
    };

详见


insns=[
{code=BPF_LDX|BPF_DW|BPF_MEM, dst_reg=BPF_REG_1, src_reg=BPF_REG_1, off=104, imm=0},
{code=BPF_STX|BPF_DW|BPF_MEM, dst_reg=BPF_REG_10, src_reg=BPF_REG_1, off=-8, imm=0},
{code=BPF_ALU64|BPF_X|BPF_MOV, dst_reg=BPF_REG_2, src_reg=BPF_REG_10, off=0, imm=0},
{code=BPF_ALU64|BPF_K|BPF_ADD, dst_reg=BPF_REG_2, src_reg=BPF_REG_0, off=0, imm=0xfffffff8},
{code=BPF_LD|BPF_DW|BPF_IMM, dst_reg=BPF_REG_1, src_reg=BPF_REG_1, off=0, imm=0x4},
{code=BPF_LD|BPF_W|BPF_IMM, dst_reg=BPF_REG_0, src_reg=BPF_REG_0, off=0, imm=0},
{code=BPF_JMP|BPF_K|BPF_CALL, dst_reg=BPF_REG_0, src_reg=BPF_REG_0, off=0, imm=0x3},
{code=BPF_ALU64|BPF_K|BPF_MOV, dst_reg=BPF_REG_0, src_reg=BPF_REG_0, off=0, imm=0},
{code=BPF_JMP|BPF_K|BPF_EXIT, dst_reg=BPF_REG_0, src_reg=BPF_REG_0, off=0, imm=0}

```


bpf系统调用调用bpf_prog_load来加载ebpf程序。
bpf_prog_load大致有以下几步:


```bash


1.调用bpf_prog_alloc为prog申请内存，大小为struct bpf_prog大小+ebpf指令总长度
2.将ebpf指令复制到prog->insns
3.调用bpf_check对ebpf程序合法性进行检查，这是ebpf的安全性的关键所在，不符ebpf规则的load失败
4.调用bpf_prog_select_runtime在线jit，编译ebpf指令成x64指令
5.调用bpf_prog_alloc_id为prog生成id，作为prog的唯一标识的id被很多工具如bpftool用来查找prog


```

ebpf从bpf的两个32位寄存器扩展到10个64位寄存器R0~R9和一个只读栈帧寄存器，并支持call指令，更加贴近现代64位处理器硬件

```cgo

R0对应rax， 函数返回值
R1对应rdi， 函数参数1
R2对应rsi， 函数参数2
R3对应rdx， 函数参数3
R4对应rcx， 函数参数4
R5对应r8， 函数参数5
R6对应rbx， callee保存
R7对应r13， callee保存
R8对应r14， callee保存
R9对应r15， callee保存
R10对应rbp，只读栈帧寄存器


##可以看到x64的r9寄存器没有ebpf寄存器对应，所以ebpf函数最多支持5个参数。

```



HIDS 开发的核心在于抓取一些高风险 syscall的参数，比如，`sys_ptrace() sys_execve()`,这些函数被glibc 包装，暴露给用户使用。当用户在glibc调用对应的函数，通过执行CPU指令完成用户态向内核态的转换。32位系统中，通过int $0x80指令触发系统调用。其中EAX寄存器用于传递系统调用号，参数按顺序赋值给`EBX、ECX、EDX、ESI、EDI、EBP`这6个寄存器。64位系统则是使用syscall指令来触发系统调用，同样使用EAX寄存器传递系统调用号`，RDI、RSI、RDX、RCX、R8、R9`这6个寄存器则用来传递参数



* Link https://www.anquanke.com/post/id/239870