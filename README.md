# pybin

linux和mac上一些常用工具命令。

## 安装教程

### 准备工作
- Python 3.6 or later

### 安装步骤
1. **Clone源码**
```sh
git clone https://github.com/zengzhifei/pybin.git
cd pybin
```

2. **安装环境**
> <small>_首次安装先使用pip或pip3安装环境依赖，重装可省略_</small>
```sh
pip3 install -r requirements.txt
```
或
```sh
pip3 install --user -r requirements.txt
```

> <small>_如果部分依赖无法安装，可尝试创建或更新~/.pip/pip.conf文件，添加以下镜像源，_</small>
```
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
```

3. **安装pybin**
```sh
python3 install.py
```

### 更新步骤
1. **更新代码**
```sh
cd pybin
git pull
```

2. **更新pybin**
```sh
python3 install.py
```

