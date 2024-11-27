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
> <small>_首次安装会提示输入密码，该密码用于生成配置文件_</small>
```sh
python3 install.py
```

3. **安装hooker**
> <small>_安装hook会再次提示输入密码（请保证和安装环境时的密码一致），该密码用于git更新代码时自动更新配置文件_</small>
```sh
securehooker config.json
```

### 更新步骤
1. **更新代码**
```sh
cd pybin
git pull
```

2. **更新环境**
```sh
python3 install.py
```

