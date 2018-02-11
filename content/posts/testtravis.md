---
title: "Testtravis"
date: 2018-02-11T16:06:33+08:00
draft: true
---


## role
按照anisble标准创建目录,目录间联系不需要管.如下面,include即可以执行了
```
ansible-galaxy init somedir
```
```
$ tree
.
├── roles
│   └── common
│       ├── handlers
│       ├── meta
│       └── tasks
│           └── main.yml
└── test.yml

5 directories, 2 files
$ cat roles/common/tasks/main.yml 
- name:
  debug: msg="helllllllo"
```
```
$ cat test.yml 
- hosts: 192.168.14.132
  roles:
    - common
```
## cron模块
```
ansible all -m cron -a 'name="jutest" hour="5" job="/bin/bash /tmp/test.sh"'
效果如下：
* 5 * * *  /bin/bash /tmp/test.sh
```
## template模块
把/mytemplates/foo.j2文件经过填写参数后，复制到远程节点的/etc/file.conf，文件权限相关略过
```
- template: src=/mytemplates/foo.j2 dest=/etc/file.conf owner=bin group=wheel mode=0644
```
跟上面一样的效果，不一样的文件权限设置方式
```
- template: src=/mytemplates/foo.j2 dest=/etc/file.conf owner=bin group=wheel mode="u=rw,g=r,o=r"
```
## setup模块

通过命令获取所有的系统信息
搜集主机的所有系统信息
```
ansible all -m setup
```
搜集系统信息并以主机名为文件名分别保存在/tmp/facts 目录
```
ansible all -m setup --tree /tmp/facts
```
#搜集和内存相关的信息
```
nsible all -m setup -a 'filter=ansible_*_mb'
```
搜集网卡信息
```
ansible all -m setup -a 'filter=ansible_eth[0-2]'

```
## archive模块
支持的格式:```gz,bz2,zip,tar```
0,压缩单个目录得到最根的目录
```
- hosts: 192.168.14.132
  tasks:
    - name: 测试压缩模块
      archive:
        path: /opt/test
        dest: /root/an/test.tar
        format: tar
解压后得到: test
```
1.压缩多个目录
```
- hosts: 192.168.14.132
  tasks:
    - name: 测试压缩模块
      archive:
        path:
            - /opt/test
            - /tmp/test2/test3/1.txt
        dest: /root/an/test.tar
        format: tar
解压后得到: /opt/test
            /tmp/test2/test3/
```
注:空文件或目录压缩不计入压缩范围.


## 发邮件
```
- hosts: node67
  remote_user: root
  tasks:
    - name: cat hosts
      shell: cat /etc/hosts
      register: info
      
    - name: sendMail to op
      mail:
        host: smtp.sina.com
        port: 25
        username: lannymxl@sina.com
        password: xatu1@
        from: lannymxl@sina.com (lannymxl)
        to: maxiaolang <maxiaolang@pp100.com>
        # cc: John Doe <j.d@example.org>, Suzie Something <sue@example.com>
        # cc: Wang Zhen <wangzhen@pp100.com>, Zhou Zhongwu <zhongzhongwu@pp100.com>
        # attach: /etc/fstab /etc/hosts
        subject: Backup-scm successfully
        body: 'System {{ ansible_hostname }}-192.168.6.67 {{ info['stdout_lines'] }}'

```


## synchronize模块
### rsync同步
```
#ansible test -m synchronize -a "src=/data/adminshell/ dest=/data/adminshell/ "
```
### rsync无差异同步
```
#ansible test -m synchronize -a "src=/data/adminshell/ dest=/data/adminshell/ delete=yes"
"msg": "*deleting   test.txt\n"
```

### 排除同步
```
#同步目录，排除某个文件
ansible test -m synchronize -a "src=/data/adminshell/ dest=/data/adminshell/ rsync_opts="--exclude=exclude.txt" "
#同步目录，排除多个文件
ansible test -m synchronize -a "src=/data/adminshell/ dest=/data/adminshell/ rsync_opts="--exclude=\*.conf,--exclude=\*.html,--exclude=test1" "
```
> 相对copy模块
* 1.copy没mode,只能发出去
* 2.copy是全量的

## replace模块
```
ansible 192.168.14.133 -m replace -a "dest=/etc/hosts regexp='^Old' replace='New' backup=yes"
```
```
#备份效果
[root@node2 tmp]# ll /etc/hosts*
-rw-r--r--  1 root root 350 Jul 20 16:56 /etc/hosts
-rw-r--r--  1 root root 312 Jul 20 16:43 /etc/hosts.63296.2017-07-20@16:44:03~
-rw-r--r--  1 root root 350 Jul 20 16:55 /etc/hosts.63677.2017-07-20@16:56:53~

```
注: copy fetch模块也有backup的功能.


## copy模块
```
#拷贝本地的/etc/hosts 文件到myserver主机组所有主机的/tmp/hosts（空目录除外）,如果使用playbooks 则可以充分利用template 模块
ansible myserver -m copy -a "src=/etc/hosts dest=/tmp/hosts mode=600 owner=ju group=ju"
#file 模块允许更改文件的用户及权限
ansible webservers -m file -a "dest=/srv/foo/a.txt mode=600"
ansible webservers -m file -a "dest=/srv/foo/b.txt mode=600 owner=ju group=ju"
#使用file 模块创建目录，类似mkdir -p
ansible webservers -m file -a "dest=/path/to/c mode=755 owner=ju group=ju state=directory"
#使用file 模块删除文件或者目录
ansible webservers -m file -a "dest=/path/to/c state=absent"
```

## raw模块
```
- hosts: node14-scm
  remote_user: root
  vars:
  - sfpath: "/backup/scm-data/*_$(date +%F -d '-1 day')_scmdata.tar.gz"
  - dfpath: "/data/backup/scm-data/"
  tasks:
    #清理远端的压缩包,远端进保留一天scm-data.tar.gz  2,远端打包并将压缩包取回
    - name: Clean | keeping [scm-server-node14]'s /backup/scm-data dir only have one tar pkg
      shell: find /backup/scm-data/ -name "*.tar.gz"  -type f -mtime -7 |xargs rm -f

    - name: Package | make /root/.scm to tar.gz package on node14
      raw: 
           cd /backup/scm-data && \
           \rm -rf .scm && \
           cp -r /root/.scm /backup/scm-data/ && \
           tar zcf /backup/scm-data/`ifconfig|sed -n '2p'|awk -F':' '{print $2}'|awk '{print $1}'`_$(date +%F -d '-1 day')_scmdata.tar.gz .scm

```
```
- hosts: node1
  task:
    - name: 清理/tmp
      raw: 
           cd /tmp && \
           \rm -rf * 

```

## tags
如果你有一个很大的playbook，而你只想run其中的某个task，这个时候tags是你的最佳选择。
此时若你希望只run其中的某个task，这run 的时候指定tags即可

```
tasks:
 
    - yum: name={{ item }} state=installed
      with_items:
         - httpd
         - memcached
      tags:
         - packages
 
    - template: src=templates/src.j2 dest=/etc/foo.conf
      tags:
         - configuration
```
```
ansible-playbook example.yml --tags "configuration,packages"   #run 多个tags
ansible-playbook example.yml --tags packages                   # 只run 一个tag
```
相反，也可以跳过某个task
```
ansible-playbook example.yml --skip-tags configuration
```
tags 和role 结合使用
tags 这个属性也可以被应用到role上，例如:
```
roles:
  - { role: webserver, port: 5000, tags: [ 'web', 'foo' ] }
```

tags和include结合使用
```
- include: foo.yml tags=web,foo
```
这样，fool.yml 中定义所有task都将被执行


## blockinfile模块
```
- hosts: 192.168.14.133
  tasks: 
  - name: Edit profile JDK conf
    blockinfile:
      dest: /etc/profile
      backup: yes
      marker: "# {mark} jdk config"
      content: |
        JAVA_HOME=/usr/java/jdk1.8.0_66
        CLASSPATH=.:$JAVA_HOME/lib/tools.jar:$JAVA_HOME/lib/dt.jar
        PATH=$JAVA_HOME/bin:$ANT_HOME/bin:$PATH
        export JAVA_HOME CLASSPATH PATH
```
```
#cat profile
...
# BEGIN jdk config
JAVA_HOME=/usr/java/jdk1.8.0_66
CLASSPATH=.:$JAVA_HOME/lib/tools.jar:$JAVA_HOME/lib/dt.jar
PATH=$JAVA_HOME/bin:$ANT_HOME/bin:$PATH
export JAVA_HOME CLASSPATH PATH
# END jdk config
```

## lineinfile模块
ansible实现sed功能
### 替换目标文件中的某行
```
- hosts: 192.168.14.132
  tasks:
    - name: seline modify enforcing
      lineinfile:
        dest: /etc/selinux/config
        regexp: '^SELINUX='
        line: 'SELINUX=enforcing'
```

### 删除一行
```
- hosts: 192.168.14.132
  tasks:
    - name: 删除一行
      lineinfile:
        path: /root/an/httpd2.conf
        state: absent
        regexp: '^an'
```
### 在目标文件某行前添加一行
```
- name: httpd.conf modify 8080
  lineinfile:
     dest: /opt/playbook/test/http.conf
     regexp: '^Listen'
     insertbefore: '^#Port'   
     line: 'Listen 8080'
  tags:
   - http8080
验证:
[root@master test]# cat http.conf 
#Listen 12.34.56.78:80
#Listen 80
Listen 8080
#Port
```

### 在目标文件某行后添加一行
```
- name: httpd.conf modify 8080
      lineinfile:
        dest: /opt/playbook/test/http.conf
        regexp: '^Listen'
        insertafter: '^#Port'   
        line: 'Listen 8080'
      tags:
        - http8080
验证:
[root@master test]# cat http.conf 
#Listen 12.34.56.78:80
#Listen 80
#Port
Listen 8080
```


## lookup templates
```
#lookups.j2 
worker_process {{ ansible_processor_cores }}
IPaddress {{ ansible_eth0.ipv4.address }}
```
```
- hosts: 192.168.14.132
  vars:
    # contents相当于f.read,将文件读取成了1个大的字符串
    contents: "{{ lookup('template','./lookups.j2') }}"
  tasks:
  - name: debug lookups
    # 使用jinja2对文件进行遍历.
    debug: msg="The contents is {% for i in contents.split("\n") %} {{ i }} {% endfor %}"

# 结果 由此可见是模板渲染后的结果做了行遍历
#"msg": "The contents is  worker_process 1  IPaddress 192.168.14.132     "
```

## authorized_key建互信
```
ansible web -m authorized_key -a "user=root state=present key=\"{{ lookup('file', '/root/.ssh/id_rsa.pub') }}\"" -k

ansible all -m authorized_key -a "user=root state=present key=\"{{ lookup('file', '/root/.ssh/id_rsa.pub') }}\"" -k    # 将本地root的公钥导入到远程用户root的authorized_keys里
ansible all -m authorized_key -a "user=root state=present key=\"{{ lookup('file', '/home/test/.ssh/id_rsa.pub') }}\"" -k # 将本地test的公钥导入到远程用户root的authorized_keys里
```
```
vi /etc/ansible/ansible.cfg
host_key_checking = False
```

## script模块
相对shell,好处是script可以集中管理脚本,过程是:将shell下发到目标机执行. 
而shell必须将shell下发下去执行
```
$　cat s.sh 
#!/bin/sh

/bin/tar -xf /tmp/opt.tar.gz -C /tmp
```
执行过程
```
$ansible 192.168.14.133 -m script -a '/tmp/s.sh' -o
192.168.14.133 | SUCCESS => {"changed": true, "rc": 0, "stderr": "Shared connection to 192.168.14.133 closed.\r\n", "stdout": "", "stdout_lines": []}
```
结果
```
$ ll
total 128
drwxr-xr-x 6 root root    157 Jul 20 17:07 opt
-rw-r--r-- 1 root root 128187 Jul 21 16:29 opt.tar.gz

```


## unarchive 解压缩
可以将本地的压缩包直接解压到远程
可以将远程压缩包直接解压
```
  src
  copy  yes|no  # yes:默认，压缩包在本地,src=本地压缩包路径，dest=解压到远程路径；no远程主机已存在压缩包，src=远程压缩包路径，dest=解压到远程路径
  creates  # 创建文件目录，当文件存在就不执行
  dest
  group
  mode
  owner  
  unarchive: src=foo.tgz dest=/var/lib/foo
  unarchive: src=/tmp/foo.zip dest=/usr/local/bin copy=no
  unarchive: src=/tmp/test.tar.gz dest=/opt/tmp/ creates=/opt/tmp/ copy=no
```