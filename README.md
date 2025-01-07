# 定位ntdll.dll中LdrpHandleTlsData地址

LdrpHandleTlsData函数主要用于解决sRDI中静态TLS问题

## 实现思路

### 32位的情况

1. 先定位字符串LdrpHandleTlsData的地址
1. 定位到指令`push LdrpHandleTlsDataAddr`的地址
   1. 即可得到LdrpHandleTlsData中的异常处理函数
   1. 这个异常函数地址被引用于EH4_SCOPETABLE中
1. 定位EH4_SCOPETABLE的地址
   1. 此地址被直接引用于LdrpHandleTlsData函数中
1. 定位指令`push EH4_SCOPETABLEAddr`即可定位到LdrpHandleTlsData函数地址

### 64位的情况

32位下异常相关结构是保存在栈中，而64位下是通过PE结构中的异常表

1. 先定位字符串LdrpHandleTlsData的地址
1. 定位到指令`lea rdx, LdrpHandleTlsDataAddr`的地址
   1. 即可得到LdrpHandleTlsData中的异常处理函数
   1. 这个异常函数地址被引用于C_SCOPE_TABLE中
1. 定位C_SCOPE_TABLE结构的地址
   1. 也就定位到UNWIND_INFO结构的地址
   1. UNWIND_INFO结构的地址被引用于RUNTIME_FUNCTION结构中
1. 定位RUNTIME_FUNCTION结构地址，即可找到LdrpHandleTlsData函数地址


## 编译

zig build -Dcpu=generic  -Doptimize=ReleaseSmall -Dtarget=x86-windows
zig build -Dcpu=generic  -Doptimize=ReleaseSmall -Dtarget=x86_64-windows

其中generic是屏蔽向量相关指令防止出现兼容性问题

## 参考链接

<https://github.com/chainreactors/wiki/blob/a471d9a237da832a06f694f40a17b5d000d9f4fa/docs/blog/todo/IoM-%E4%BB%8E%E4%B8%80%E4%B8%AA%E5%B4%A9%E6%BA%83%E5%BC%80%E5%A7%8B%E7%9A%84%20PE%20Loader%20%E6%95%91%E8%B5%8E%E4%B9%8B%E6%97%85.md>