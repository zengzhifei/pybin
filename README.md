# pybin

提供linux和mac上一些常用运维工具命令和开发SDK。

## 安装教程

### 准备工作
- Python 3.6 or later

### 安装步骤
1. **Clone源码**
```sh
git clone git@github.com:zengzhifei/pybin.git
or
git clone https://github.com/zengzhifei/pybin.git
cd pybin
```

2. **安装环境**
> <small>_首次安装先使用pip或pip3安装环境依赖，重新安装可省略_</small>
```sh
pip3 install -r requirements.txt
```
或
```sh
pip3 install --user -r requirements.txt
```

> <small>_如果部分依赖无法安装，可尝试创建或更新~/.pip/pip.conf文件，添加镜像源，如：_</small>
```
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
```

3. **安装pybin**
```sh
python3 install.py
```

### 更新步骤
1. **拉取最新代码**
```sh
cd pybin
git pull
```

2. **更新pybin**
```sh
python3 install.py
```
或
```sh
pybin -i
```

### 查看更多
><small>_查看作者信息，工具版本，提供命令等内容，可执行如下命令:_</small>
```sh
pybin --help
```