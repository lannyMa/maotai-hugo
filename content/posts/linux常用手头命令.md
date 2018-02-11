---
title: "linux常用手头命令"
subtitle: "着急用的时候查的,查到后解决了问题做的笔录"
description: "linux常用手头命令,着急用的时候查的,查到后解决了问题做的笔录"
date: 2018-02-10T14:49:15+08:00
tags: ["linux","svc"]
categories: "Linux"
bigimg: [{src: "https://ws1.sinaimg.cn/large/9e792b8fgy1fobeuq0l1wj218g0tu1ky.jpg", desc: ""}]
draft: false
---



[相关代码](https://github.com/lannyMa/scripts)


## centos7修改网卡名字
```
net.ifnames=0 biosdevname=0
```


## man手册中文
参考:http://www.kernel.org/pub/linux/docs/man-pages/
http://blog.csdn.net/gatieme/article/details/51656707
```
yum install man-pages-zh-CN -y
echo 'LANG="zh_CN.UTF-8"' >> ~/.bashrc
echo 'LANGUAGE="zh_CN:zh"' >> ~/.bashrc
source ~/.bashrc
```
## stress压测工具
```
[root@n1 kubernetes]# yum install stress -y
[root@n1 kubernetes]# stress -h
stress: FAIL: [70121] (244) unrecognized option: -h
[root@n1 kubernetes]# stress --help
`stress' imposes certain types of compute stress on your system

Usage: stress [OPTION [ARG]] ...
 -?, --help         show this help statement
     --version      show version statement
 -v, --verbose      be verbose
 -q, --quiet        be quiet
 -n, --dry-run      show what would have been done
 -t, --timeout N    timeout after N seconds
     --backoff N    wait factor of N microseconds before work starts
 -c, --cpu N        spawn N workers spinning on sqrt()
 -i, --io N         spawn N workers spinning on sync()
 -m, --vm N         spawn N workers spinning on malloc()/free()
     --vm-bytes B   malloc B bytes per vm worker (default is 256MB)
     --vm-stride B  touch a byte every B bytes (default is 4096)
     --vm-hang N    sleep N secs before free (default none, 0 is inf)
     --vm-keep      redirty memory instead of freeing and reallocating
 -d, --hdd N        spawn N workers spinning on write()/unlink()
     --hdd-bytes B  write B bytes per hdd worker (default is 1GB)

Example: stress --cpu 8 --io 4 --vm 2 --vm-bytes 128M --timeout 10s

Note: Numbers may be suffixed with s,m,h,d,y (time) or B,K,M,G (size).
```


## 安装python-ldap
参考: https://stackoverflow.com/questions/4768446/i-cant-install-python-ldap
```
yum install python-devel openldap-devel
```


## nginx配置安全检查工具
```
pip install gixy
gixy /usr/local/nginx/conf/nginx.conf

可以检查到以下一些问题:

- ssrf 服务端请求伪造
- HTTP Splitting 响应拆分
- 错误的 referrer/origin 验证
- 错误使用 add_header 指令
- Host 头信息伪造
- Referer 验证中允许为空
- 响应头中使用多行形式

```

## 禁用ipv6

参考: https://linux.cn/article-4935-1.html
```

vi /etc/sysctl.conf

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
sysctl -p

sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
```


## curl命令-网站如果3次不是200或301则报警
```
curl -o /dev/null -s -w "%{http_code}" baidu.com
-k/--insecure   允许不使用证书到SSL站点
-H/--header     自定义头信息传递给服务器
-I/--head       只显示请求头信息
-w/--write-out [format] 什么输出完成后
-s/--silent     静默模式。不输出任何东西
-o/--output     把输出写到该文件中
```

## linux正则
参考: http://blog.csdn.net/Hello_Hwc/article/details/40017833
- 基本

```
. 匹配任何单个字符
* 前面出现0个或者多个
^ 以..开始
$ 以..结束
```


- 举个例子

```
china  :  匹配此行中任意位置有china字符的行

^china : 匹配此以china开关的行

china$ : 匹配以china结尾的行

^china$ : 匹配仅有china五个字符的行

[Cc]hina : 匹配含有China或china的行

Ch.na : 匹配包含Ch两字母并且其后紧跟一个任意字符之后又有na两个字符的行

Ch.*na : 匹配一行中含Ch字符，并且其后跟0个或者多个字符，再继续跟na两字符
```

- 扩展正则
```
? : 匹配前面正则表达式的零个或一个扩展
+ : 匹配前面正则表达式的一个或多个扩展
{n,m}: 前面出现1个或2个或3个
| : 匹配|符号前或后的正则表达式
( ) : 匹配方括号括起来的正则表达式群
```

## grep
- 参数

```
-n, --line-number
-i, --ignore-case   不区分大小写
-r, --recursive     按照目录
-o, --only-matching 只显示匹配行中匹配正则表达式的那部分
-v, --invert-match  排除
-c, --count         统计url出现次数
grep -nr
grep -oP
```

- 过滤ip

```
192.168.100.100
ifconfig|grep -oP "([0-9]{1,3}\.){3}[0-9]{1,3}"
```

- 过滤邮箱

```
cat >>tmp.txt<<EOF
iher-_@qq.com
hello
EOF

cat tmp.txt|grep -oP "[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\.[a-zA-Z]+)+"
```

- 统计baidu关键字的url在这个大文件中出现的次数

```
$ cat >file.txt<<EOF
wtmp begins Mon Feb 24 14:26:08 2014
192.168.0.1
162.12.0.123
"123"
123""123
njuhwc@163.com
njuhwc@gmil.com 123
www.baidu.com
tieba.baidu.com
www.google.com
www.baidu.com/search/index
EOF

grep -cn ".*baidu.com.*" file.txt
3
```

## bash自动补全
```
 yum install bash-com* -y

 我在dokcer命令tab可以补全了
```

## nginx json日志格式标准版
参考: https://github.com/kubernetes/ingress-nginx/blob/master/docs/user-guide/configmap.md
```
log-format-upstream: '{ "time": "$time_iso8601", "remote_addr": "$proxy_protocol_addr",
    "x-forward-for": "$proxy_add_x_forwarded_for", "request_id": "$request_id", "remote_user":
    "$remote_user", "bytes_sent": $bytes_sent, "request_time": $request_time, "status":
    $status, "vhost": "$host", "request_proto": "$server_protocol", "path": "$uri",
    "request_query": "$args", "request_length": $request_length, "duration": $request_time,
    "method": "$request_method", "http_referrer": "$http_referer", "http_user_agent":
    "$http_user_agent" }'
```


## elk启动
```
nohup /bin/su - elk -c "/usr/local/elasticsearch/bin/elasticsearch" > /data/es/es-start.log 2>&1 &
nohup /bin/su - elk -c "/usr/local/kibana/bin/kibana" > /data/es/kibana-start.log 2>&1 &
nohup "/usr/local/logstash/bin/logstash -f /data/es/conf/logstash/logstash.conf" > /data/es/logstash-start.log 2>&1 &



curl -XDELETE http://192.168.100.204:9200/.monitoring-kibana-6-2017.10.23

健康:
http://192.168.100.204:9200/_cat/health?v

节点:
http://192.168.100.204:9200/_cat/nodes?v


查看index:
http://192.168.100.204:9200/_cat/indices?v

```


## 修改网卡名字

    vim /etc/udev/rules.d/70-persistent-net.rules

    vim /etc/sysconfig/network-scripts/ifcfg-eth0




## sshfs挂载(实现nfs效果)

- 仅需客户端配置(已做客户端sshkey无密访问服务端)

```
yum install -y sshfs

  挂载
sshfs -o allow_other,transform_symlinks root@192.168.14.133:/data /data
  卸载
fusermount -u /data
```
参考: https://www.91yun.co/archives/8731




```
我在logging模块里看到的这个注释

#---------------------------------------------------------------------------
# Configuration classes and functions
#---------------------------------------------------------------------------
```

## python搜路径
```
起因是有人问怎么把函数全局化,不用import即可随处调用

os.getcwd() #当前py所在目录

b.__file__ #这个模块的路径

os.__module__ #这个函数在哪个模块
```
参考:http://blog.csdn.net/l_b_yuan/article/details/52260646
```
os.path.abspath(path)  #返回绝对路径
os.path.split(path     #将path分割成目录和文件名二元组返回
os.path.dirname(path)  #返回path的目录。其实就是os.path.split(path)的第一个元素
os.path.basename(path) #返回path最后的文件名
os.path.exists(path)   #如果path存在，返回True；如果path不存在，返回False
os.path.isabs(path)    #如果path是绝对路径，返回True
os.path.isfile(path)   #如果path是一个存在的文件，返回True。否则返回False
os.path.isdir(path)    #如果path是一个存在的目录，则返回True。否则返回False
os.path.getatime(path) #返回path所指向的文件或者目录的最后存取时间
os.path.getmtime(path) #返回path所指向的文件或者目录的最后修改时间
s.path.join(path1[, path2[, ...]])  #将多个路径组合后返回，第一个绝对路径之前的参数将被忽略。
>>> os.path.join('c:\\', 'csv', 'test.csv')
'c:\\csv\\test.csv'
>>> os.path.join('windows\temp', 'c:\\', 'csv', 'test.csv')
'c:\\csv\\test.csv'
>>> os.path.join('/home/aa','/home/aa/bb','/home/aa/bb/c')
'/home/aa/bb/c'
```


## python env  和 vscode配置
```
pip install virtualenv
pip install virtualenvwrapper
pip install virtualenvwrapper-win
mkvirtualenv --python==C:\Python27\python.exe py27env
exit
mkvirtualenv --python==C:\Python34\python.exe py34env

workon


{
    "workbench.colorTheme": "Solarized Light",
    "window.zoomLevel": 1,
    "window.menuBarVisibility": "default",
    "editor.wordWrap": "on",
    "editor.fontSize": 16,
    "files.autoSave": "afterDelay",
    "terminal.integrated.shell.windows": "C:\\Program Files\\Git\\bin\\bash.exe",
    "editor.rulers": [80,120]
}
```


## env配置文件
```
•    ~/.bash_profile：用户每次登录时执行
•    ~/.bashrc：每次进入新的Bash环境时执行
•    ~/.bash_logout：用户每次退出登录时执行
```

## sedmail发邮件配置
```
yum install sendmail -y
cat >>/etc/mail.rc<<EOF

set from=xxx@tt.com
set smtp=smtp.exmail.qq.com
set smtp-auth-user=xxx@tt.com
set smtp-auth-password=123456
set smtp-auth=login
EOF
source /etc/mail.rc
```

- 发消息

```
echo "test"| mail -s "邮件标题" iher@foxmail.com
```

- 发文件

```
mail -s "邮件标题" iher@foxmail.com < /etc/passwd
```

- 发附件

```
mail -s "邮件标题" -a /var/log/messages iher@Foxmail.com < /etc/passwd
```

- 邮件相关目录

```
C6 postfix /var/spool/postfix/maildrop
C5 sedmail /var/spool/clientmqueue
```
注: centos6.5已经不自动安装sendmail了所以没必要走这一步优化

- 写脚本自动清理邮箱

```
mkdir -p /server/scripts

cat /root/shell/spool_clean.sh

#!/bin/sh
find/var/spool/clientmqueue/-type f -mtime +30|xargs rm-f
```

```
echo '*/30 * * * * /bin/sh /server/scripts/spool_clean.sh >/dev/null 2>&1'>>/var/spool/cron/root
```

## locale字符集-面试

- 查本地支持的所有字符集

```
# locale -a
```

- 查当前使用的字符集

```
locale #调取了/etc/sysconfig/i18n
```

- 系统默认字符集:

```
export LANG='zh_CN.UTF-8'
```

## 监控网卡实时流量

- 监控网卡流量历史流量

```
yum install sysstat
sar -n DEV 1 5  #1s监控1次,共监控5次.
sar -n DEV  (-n network)
```
```
watch more /proc/net/dev
```


## find干掉超过10天的
- mtime 10天内  10天外

```
find . -mtime +10 -exec rm -rf {} \;
find . -mtime +10|xargs rm -f
```
![](http://ww1.sinaimg.cn/large/9e792b8fgy1fj7blirtkaj20gc06lwf7)



## 测试udp端口是否通-面试

```
$ nc -vuz 192.168.6.6 53
Connection to 192.168.6.6 53 port [udp/domain] succeeded!
```
实际使用时可以只用-u参数，-u代表udp协议 ，-v代表详细模式，-z代表只监测端口不发送数据。


## 使用nc+tar传文件
- client发交互式到服务器的console

```
nc -l -u 8021             --server #可以配置tcpdump -i eth0 port 8021 -nnv抓包
nc -u 192.168.6.52 8021   --client #交互式发送消息
```
- client发文件到服务端console

```
server: nc -l -u 8021
client: nc -u 192.168.6.52 8021 < /etc/hosts
```
- tar+nc传文件

```
server： tar -cf - /home/database  | nc -l 5677 #将/home/database文件
client： nc 192.168.6.52 5677 | tar -xf -       #传到client的当前目录
```

## 生成密码：
```
openssl rand -hex 8
```

```
$mkpasswd -l 16 -s 2
3Hte^bd-pkylSbf7
```

```
echo "ansible"|passwd --stdin ansible #centos7改用户密码
```

## fstab挂载

- fstab挂载硬盘

```
cat /etc/fstab
需挂载的设备                挂载点  fs类型   参数        备份 检查
/dev/mapper/centos-data    /data  xfs      defaults    0 0
```

- nfs挂载(centos7放fstab)

```
192.168.8.68:/data/backup/no75/confluence/data /data/confluence/  nfs     defaults        0 0
```

- nfs挂载(centos6放/etc/rc.local里即可)

```
/usr/bin/mount -t nfs 192.168.8.68:/data/owncloud /data/owncloud-192.168.8.68
```

- nfs服务端设置:

```
/data/backup/no75/confluence/data 192.168.8.0/24(rw,sync,no_root_squash)
```

- (磁盘扩容)关于tmpfs空间满，会影响其中的服务使用吗

```
Filesystem Size Used Avail Use% Mounted on
/dev/sda1 32G 1.3G 29G 5% /
tmpfs 16G 16G 0 100% /dev/shm

mount -o remount,size=18G /dev/shm
```

- 只读mount

```
Mount the file system and make it writeable
mount -uw /

Make the filesystem read only again.
mount -ur /
```


## date命令小结
- 前一天日期

```
date  +%Y-%m-%d~%H-%M-%S -d "-1 day"
```
```
date  "+%Y-%m-%d %H-%M-%S" -d "-1 day"
```
- 压缩带日期
```
tar zcvf etc_$(date +%F -d "-1 day").tar.gz /etc/
```

## 系统时间优化
- 时区校准

```
rm -rf /etc/localtime && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && ntpdate ntp1.aliyun.com
```
- 设置同步时间

```
/user/sbin/ntpdate ntp1.aliyun.com
echo '*/5 * * * * /usr/sbin/ntpdate ntp1.aliyun.com >/dev/null 2 >&1' >>/var/spool/cron/root
```

- 手动修改时间

```
date -s "2016/06/11 22:50"
```

## 过滤网卡ip
```
ifconfig eth0|grep -oP "([0-9]{1,3}\.){3}[0-9]{1,3}"|sed -n '1p'
ifconfig|sed -n '2p'|sed -r 's#^.*addr:(.*) Bcast.*$#\1#g'
ifconfig|sed -n '2p'|awk -F':' '{print $2}'|awk '{print $1}'
```

## 回车擦除^H
```
echo "stty erase ^H" >>/root/.bash_profile
source /root/.bash_profile
```

## centos7安装nslookup ifconfig
How to install dig, host, and nslookup – bind-utils on CentOS:
```
yum install bind-utils -y [c6使用nslookup]
yum install net-tools -y [c7使用ifconfig]
```

## selinux优化
```
setenforce 0
sed -i 's#SELINUX=enforcing#SELINUX=disabled#g' /etc/selinux/config
getenforce
/etc/init.d/iptables stop
```

## 文件描述符优化
```
ulimit -SHn 65535
echo '* - nofile 65536' >>/etc/security/limits.conf

echo "* soft nproc 65535" >>/etc/security/limits.conf
echo "* hard nproc 65535" >>/etc/security/limits.conf
echo "* soft nofile 65535" >>/etc/security/limits.conf
echo "* hard nofile 65535" >>/etc/security/limits.conf
```

## 清除系统版本banner
```
> /etc/issuse
>/etc/redhat-release
```

## 添加普通用户并进行sudo授权管理

```
$ useradd sunsky
$ echo "123456"|passwd --stdin sunsky&&history –c
$ visudo # 99gg
在root ALL=(ALL) ALL  #此行下，添加如下内容
sunsky ALL=(ALL) ALL
lanny  ALL=(ALL) ALL=/sbin/mount /mnt/cdrom, /sbin/umount /mnt/cdrom #仅允许他执行这些命令
```

## ssh慢优化
```
\cp /etc/ssh/sshd_config /etc/ssh/sshd_config.ori
sed -i 's#\#UseDNS yes#UseDNS no#g' /etc/ssh/sshd_config
sed -i 's#GSSAPIAuthentication yes#GSSAPIAuthentication no#g' /etc/ssh/sshd_config
/etc/init.d/sshd restart


Port 22345
PermitRootLogin no
PermitEmptyPasswords no
UseDNS no
ListenAddress 192.168.138.24
GSSAPIAuthentication no
```

## crt设置超时
```
export TMOUT=10
echo "export TMOUT=10" >>/etc/profile
source /etc/profile
```

## vim安装优化
```
yum -y install vim-enhanced
cat >>/etc/vimrc<<a
set nu
set cursorline
set nobackup
set ruler
set autoindent
set vb t_vb=
set ts=4
set expandtab
set paste
a
. /etc/vimrc
```

## rsync安装配置

- rsync server配置(rpm -qa|grep rsync):

```
cat /usr/local/rsync/rsync.conf


uid = root
gid = root
use chroot = no
max connections = 10
strict modes = yes
pid file = /var/run/rsyncd.pid
lock file = /var/run/rsync.lock
log file = /var/log/rsyncd.log
[web]
path = /code/pp100web/target/ROOT
comment = web file
ignore errors
read only = no
write only = no
hosts allow = 192.168.14.132
list = false
uid = root
gid = root
auth users = webuser
secrets file = /usr/local/rsync/rsync.passwd
```

- 重启rsync

```
kill -HUP `cat /var/run/rsyncd.pid`
/usr/bin/rsync --daemon --config=/usr/local/rsync/rsync.conf

ps -ef|grep rsync
```

- 配置允许同步的的客户端

```
vim /usr/local/rsync/rsync.conf
hosts allow = 192.168.14.132,192.168.14.133
```
注意:密码文件统一600,且普通用户为谁,属主即为谁.



## java环境变量(附带tomcat)

```
export JAVA_HOME=/usr/local/jdk
export PATH=$JAVA_HOME/bin:$JAVA_HOME/jre/bin:$PATH
export CLASSPATH=.$CLASSPATH:$JAVA_HOME/lib:$JAVA_HOME/jre/lib:$JAVA_HOME/lib/tools.jar
export TOMCAT_HOME=/usr/local/tomcat
export CATALINA_BASE="/data/tomcat"
export PATH=/usr/local/mysql/bin:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/jdk1.7.0_45/bin:/root/bin:/usr/local/jdk1.7.0_45/bin:/root/bin
```


## 换源&安装常用软件
```
wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-6.repo
wget -O /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-6.repo
yum clean all
yum makecache
yum install lrzsz ntpdate sysstat dos2unix wget telnet tree -y
```

## 添加定时任务
```
crontab -l
*/5 * * * * /usr/sbin/ntpdate times.windows.com >/dev/null 2>&1
```

## 优化退格键
```
stty erase "^H" #追加到/etc/profile
```
## 优化history:
```
export HISTTIMEFORMAT="%F %T `whoami` "
echo "export HISTTIMEFORMAT="%F %T `whoami` "" >> /etc/profile
```
## 优化message:格式
```
export PROMPT_COMMAND='{ msg=$(history 1 | { read x y; echo $y; });logger "[euid=$(whoami)]":$(who am i):[`pwd`]"$msg";}'
```

## 过滤日志
```
cat /etc/salt/master |grep -v "#" | sed '/^$/d'

grep -nir
-i 不区分大小写
-n 显示行号
-r 查找目录, grep -r 'xx' .
```

## kill服务
```
/usr/bin/killall -HUP syslogd
/bin/kill -USR1 $(cat /var/run/nginx.pid 2>/dev/null) 2>/dev/null || :
```

## 禁止ping
```
echo "net.ipv4.icmp_echo_ignore_all=1">>/etc/sysctl.conf
tail -1 /etc/sysctl.conf
sysctl -p
echo 1 > /proc/sys/net/ipv4/ip_forward #这样好处可以tab
```

```
sysctl -w net.ipv4.ip_forward=1 #好像没写到/etc/sysctl.conf里
```

## sed 在某行（指具体行号）前或后加一行内容
```
sed -i 'N;4addpdf' a.txt
sed -i 'N;4ieepdf' a.txt
sed -i 'N;4a44444444444444444444444444testt' 1.log在第四行后加一行
http://www.361way.com/sed-process-lines/2263.html
```




## 关闭bell:[需reboot]
```
sed -i 's#^\#set bell-style none#set bell-style none#g' /etc/inputrc
echo "modprobe -r pcspkr" > /etc/modprobe.d/blacklist
```


## 关掉ctrl+alt+delete关机
```
\cp /etc/init/control-alt-delete.conf /etc/init/control-alt-delete.conf.bak
sed -i 's#exec /sbin/shutdown -r now "Control-Alt-Deletepressed"#\#exec /sbin/shutdown -r now "Control-Alt-Deletepressed"#g'
```
```
yum groupinstall base -y
yum groupinstall core -y
yum groupinstall development libs -y
yum groupinstall development tools -y
```

## echo高亮显示
```
echo -e "\033[32m crontab has been added successfully \033[0m"
```

## nfs安装配置
- 服务端&客户端

```
yum install nfs-utils rpcbind -y
```
- 服务端:

```
/etc/init.d/rpcbind start
ps -ef |grep rpc
/etc/init.d/rpcbind status
rpcinfo -p localhost
```

- 服务端配置共享目录

```
echo "/data 10.0.0.0/24(rw,sync,no_root_squash)" >> /etc/exports
chkconfig rpcbind on
chkconfig nfs on
```

- 客户端挂载

```
/etc/init.d/rpcbind start
chkconfig rpcbind on
showmount -e 10.1.1.10
mount -t nfs 10.1.1.10:data /mnt

写到/etc/rc.local里
```

## nginx编译安装
- 1.安装依赖

```
yum install pcre pcre-devel openssl openssl-devel –y
```

- 2.添加nginx用户

```
useradd -s /sbin/nologin -M nginx
```

- 3.编译安装

```
./configure --user=nginx --group=nginx --prefix=/usr/local/nginx-1.6.2 --with-http_stub_status_module --with-http_ssl_module
make && make install
echo $?
ln -s /usr/local/nginx-1.6.2 /usr/local/nginx
```

- 4.检查nginx.conf语法

```
/usr/local/sbin/nginx       # -t检查配置文件语法
/usr/local/nginx/sbin/nginx # 启动
```

- 5.添加nginx服务到PATH

```
echo PATH=/application/nginx/sbin/:$PATH >> /etc/profile
source /etc/profile

netstat -ntulp |grep nginx
lsof -i:80
curl 192.168.14.151
nginx -s stop
nginx -s reload
```

- 7.nginx反代配置nignx.conf

```
worker_processes auto;
events {
  multi_accept on;
  use epoll;
  worker_connections 51200;
}
error_log stderr notice;

worker_rlimit_nofile 65535;

http {
    include       mime.types;
    default_type  application/octet-stream;
    server_info  off;
    server_tag   off;
    server_tokens  off;
    server_name_in_redirect off;
    client_max_body_size 20m;
    client_header_buffer_size 16k;
    large_client_header_buffers 4 16k;
    sendfile        on;
    tcp_nopush     on;
    keepalive_timeout  65;
    server_tokens on;
    gzip  on;
    gzip_min_length 1k;
    gzip_buffers 4 16k;
    gzip_proxied   any;
    gzip_http_version 1.1;
    gzip_comp_level 3;
    gzip_types text/plain application/x-javascript text/css application/xml;
    gzip_vary on;

    upstream owncloud {
        server 127.0.0.1:8000;
    }

    upstream confluence {
        server 127.0.0.1:8090;
    }


    server {
        listen       80;
        server_name  owncloud.maotai.org;
        location / {
            proxy_next_upstream error timeout invalid_header http_500 http_503 http_404 http_502 http_504;
            proxy_pass http://owncloud;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
    server {
        listen       80;
        server_name  confluence.maotai.org;
        location / {
            proxy_next_upstream error timeout invalid_header http_500 http_503 http_404 http_502 http_504;
            proxy_pass http://confluence;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
    server {
        listen  80;
        server_name status-no189.maotai.org;
        location /nginx_status {
            stub_status on;
            access_log off;
        }
    }
}
```

## 徒手生成10M的文件
参考: https://linux.cn/article-4126-1.html
```
head -c 10M < /dev/urandom > /var/log/log-file

# 生成随机字符串
cat /dev/urandom |tr -dc [:alnum:] |head -c 8
```

## logrotate nginx日志切割
每天3点才切割问题: 参考: http://www.voidcn.com/article/p-tpivuevp-gn.html
```
cat > /etc/logrotate.d/nginx
/usr/local/nginx/logs/*.log {
    daily
    missingok
    rotate 7
    dateext
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        if [ -f /usr/local/nginx/logs/nginx.pid ]; then
            kill -USR1 `cat /usr/local/nginx/logs/nginx.pid`
        fi
    endscript
}
```

## 网卡配置
```
DEVICE=eth0
TYPE=Ethernet
ONBOOT=yes
NM_CONTROLLED=yes
BOOTPROTO=static
IPADDR=192.168.6.28
NETMASK=255.255.255.0
GATEWAY=192.168.6.1
```


## 修改console提示符
- Ubuntu的promote

```
export PS1="\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\u@\h:\w\$"
```
- centos的promote

```
export PS1="[\u@\h \W]\$"
```

## yum安装lamp

- yum安装lamp:

```
yum install -y httpd php php-cli php-common php-pdo php-gd
yum install -y httpd php php-cli php-common php-pdo php-gd mysql mysql-server php-mysql
yum install -y httpd php php-ldap php-gd
```

- php配置:

```
vim /etc/php.ini
729 post_max_size = 16M
946 date.timezone = PRC #(中华人民共和国)
```

## 批量创建用户脚本
```
cat adduser.sh

#!/bin/bash
# Add system user
for ldap in {1..5};do
if id user${ldap} &> /dev/null;then
echo "System account already exists"
else
adduser user${ldap}
echo user${ldap} | passwd --stdin user${ldap} &> /dev/null
echo "user${ldap} system add finish"
fi
done
# chmod +x adduser.sh
# ./adduser.sh
# id user1
uid=502(user1) gid=502(user1) groups=502(user1)
```

```
useradd test -u 6000 -g 6000 -s /sbin/nologin -M -d /dev/null
```

## [shell] $*和$@的区别


- 单独的  $*和$@ 没区别
- "$*"和"$@"区别如下


```
[root@node1 ~]# cat test.sh
#!/bin/sh

for i in "$*";do
echo $i
done
[root@node1 ~]# sh test.sh 1 2 3 4
1 2 3 4

[root@node1 ~]# cat test.sh
#!/bin/sh

for i in "$@";do
echo $i
done
[root@node1 ~]# sh test.sh 1 2 3 4 5
1
2
3
4
5
```

## [shell] [linux exec与重定向](http://xstarcd.github.io/wiki/shell/exec_redirect.html)

## [shell] [shell学习之变量](http://lovelace.blog.51cto.com/1028430/1211141)

## [shell] 定义列表

- 使用小括号为数组赋值

```a=（1 2 3）```注意: 默认空格隔开

- 为数组b赋值-方法1

```
$ b=(bbs www http ftp)
$ echo ${b[*]}
bbs www http ftp
```

- 打印出第一个和第三个数据项

```
$ echo ${b[0]};echo '*******';echo ${b[2]}
bbs
*******
http
```
注: 记住是小括号，不是大括号


- 为数组b赋值-方法2

```
name=(
alice
bob
cristin
danny
)

for i in "${!name[@]}";do
echo ${name[$i]}
done
```

- 取得数组元素的个数-方法1

```
length=${#array_name[@]}
```

- 取得数组元素的个数-方法2

```
length=${#array_name[*]}
```

- 取得数组单个元素的长度

```
lengthn=${#array_name[n]}
```



优化小结:
一清： 定时清理日志/var/spool/clientsqueue
一精： 精简开机启动服务
一增： 增大文件描述符
两优： linux内核参数的优化、yum源优化
四设：设置系统的字符集、设置ssh登录限制、设置开机的提示信息与内核信息、设置block的大小
七其他：文件系统优化、sync数据同步写入磁盘、不更新时间戳、锁定系统关键文件、时间同步、sudo集权管理、关闭防火墙和selinux


[本文 centos 6.5 优化 的项有18处:](http://www.lvtao.net/server/centos-server-setup.html)
- 1、centos6.5最小化安装后启动网卡
- 2、ifconfig查询IP进行SSH链接
- 3、更新系统源并且升级系统
- 4、系统时间更新和设定定时任
- 5、修改ip地址、网关、主机名、DNS
- 6、关闭selinux，清空iptables
- 7、创建普通用户并进行sudo授权管理
- 8、修改SSH端口号和屏蔽root账号远程登陆
- 9、锁定关键文件系统（禁止非授权用户获得权限）
- 10、精简开机自启动服务
- 11、调整系统文件描述符大小
- 12、设置系统字符集
- 13、清理登陆的时候显示的系统及内核版本
- 14、内核参数优化
- 15、定时清理/var/spool/clientmqueue
- 16、删除不必要的系统用户和群组
- 17、关闭重启ctl-alt-delete组合键
- 18、设置一些全局变量

## 优化内核:
```
\cp /etc/sysctl.conf /etc/sysctl.conf.$(date +%F)
cat >>/etc/sysctl.conf<<EOF
net.ipv4.tcp_fin_timeout = 2
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.ip_local_port_range = 4000 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 36000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 16384
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_orphans = 16384
net.netfilter.nf_conntrack_max = 25000000
net.netfilter.nf_conntrack_tcp_timeout_established = 180
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
EOF
sysctl -p
```
注: 以下参数是对centos6.x的iptables防火墙的优化，防火墙不开会有提示，可以忽略不理。
如果是centos5.X需要吧netfilter.nf_conntrack替换成ipv4.netfilter.ip
centos5.X为net.ipv4.ip_conntrack_max = 25000000

```
net.nf_conntrack_max = 25000000
net.netfilter.nf_conntrack_max = 25000000
net.netfilter.nf_conntrack_tcp_timeout_established = 180
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
```



## linux更换内核

[参考](https://www.91yun.co/archives/795)

**CentOS6** 内核更换为： 2.6.32-504.3.3.el6.x86_64

```
rpm -ivh http://soft.91yun.org/ISO/Linux/CentOS/kernel/kernel-firmware-2.6.32-504.3.3.el6.noarch.rpm
rpm -ivh http://soft.91yun.org/ISO/Linux/CentOS/kernel/kernel-2.6.32-504.3.3.el6.x86_64.rpm --force

```

**CentOS7** 内核更换为： 3.10.0-229.1.2.el7.x86_64

```
rpm -ivh http://soft.91yun.org/ISO/Linux/CentOS/kernel/kernel-3.10.0-229.1.2.el7.x86_64.rpm --force

```

##### 查看是否成功

```
reboot
uname -r
rpm -qa | grep kernel

百度:
site:centos.org 你需要的内核
site:centos.org kernel-2.6.32-504.3.3.el6.x86_64.rpm
```

