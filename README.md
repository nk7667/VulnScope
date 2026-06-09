# VulnScope

自动化黑盒漏洞扫描平台，支持分布式部署，基于 Go + Vue + Redis + MySQL。

## 架构

```
用户 → API Server → Scheduler → Redis 队列 → Worker → 扫描器(nmap/nuclei)
                                                    ↓
                                              结果写入 MySQL
```

扫描流水线：域名解析 → 存活探测 → 端口扫描(nmap) → 指纹识别(nuclei) → 漏洞扫描(nuclei)

## 环境依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| Go | 1.22+ | 后端编译 |
| Node.js | 18+ | 前端编译 |
| Redis | 5.0+ | 任务队列(Asynq) |
| MySQL | 8.0+ | 数据存储 |
| nmap | 可选 | 端口扫描 |
| nuclei | 可选 | 指纹识别 + 漏洞扫描 |

## 快速开始

### 1. 部署 MySQL

**Linux (Ubuntu/Debian):**

```bash
# 安装 MySQL
sudo apt update && sudo apt install -y mysql-server

# 启动服务
sudo systemctl start mysql
sudo systemctl enable mysql

# 初始化数据库和用户
sudo mysql -e "CREATE DATABASE IF NOT EXISTS scanner CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
sudo mysql -e "CREATE USER IF NOT EXISTS 'scanner'@'localhost' IDENTIFIED BY 'scanner123';"
sudo mysql -e "GRANT ALL PRIVILEGES ON scanner.* TO 'scanner'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# 导入建表语句
mysql -u scanner -pscanner123 scanner < schema.sql
```

**Windows:**

```powershell
# 安装 MySQL 8.0+ 后，以管理员身份运行
& "C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe" -u root -e "CREATE DATABASE IF NOT EXISTS scanner CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS 'scanner'@'localhost' IDENTIFIED BY 'scanner123'; GRANT ALL PRIVILEGES ON scanner.* TO 'scanner'@'localhost'; FLUSH PRIVILEGES;"

# 导入建表语句
& "C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe" -u scanner -pscanner123 scanner < schema.sql
```

**Docker:**

```bash
docker run -d --name mysql \
  -e MYSQL_ROOT_PASSWORD=root123 \
  -e MYSQL_DATABASE=scanner \
  -e MYSQL_USER=scanner \
  -e MYSQL_PASSWORD=scanner123 \
  -p 3306:3306 \
  mysql:8.0 --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci

# 导入建表语句
docker exec -i mysql mysql -u scanner -pscanner123 scanner < schema.sql
```

### 2. 部署 Redis

**Linux:**

```bash
sudo apt install -y redis-server
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

**Windows:**

下载 [Redis for Windows](https://github.com/tporadowski/redis/releases)，解压后运行：

```powershell
redis-server.exe
```

**Docker:**

```bash
docker run -d --name redis -p 6379:6379 redis:7
```

### 3. 安装扫描工具（可选但推荐）

```bash
# 安装 nmap
# Linux
sudo apt install -y nmap
# macOS
brew install nmap
# Windows: 从 https://nmap.org/download.html 下载安装

# 安装 nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 下载 nuclei 模板
nuclei -update-templates
```

### 4. 编译和启动

```bash
# 克隆项目
git clone git@github.com:nk7667/VulnScope.git
cd VulnScope

# 编译后端
go build -o vulnscope ./cmd/scanner/

# 编辑配置文件（修改数据库连接、扫描工具路径等）
cp config.yaml.example config.yaml
vim config.yaml

# 启动（单机模式）
./vulnscope -mode=all
```

### 5. 启动前端

```bash
cd web
npm install
npm run dev
```

访问 http://localhost:5173 即可使用。

## 配置说明

配置文件：`config.yaml`

```yaml
mode: all                    # 运行模式: server / worker / all
server:
  addr: ":8088"              # API 监听地址
database:
  driver: mysql
  dsn: "scanner:scanner123@tcp(127.0.0.1:3306)/scanner?charset=utf8mb4&parseTime=True&loc=Local"
redis:
  addr: "127.0.0.1:6379"
  password: ""
  db: 0
worker:
  concurrency: 10            # 最大并发任务数
  max_retry: 3               # 失败重试次数
scanner:
  nmap_path: nmap            # nmap 可执行文件路径
  nuclei_path: nuclei        # nuclei 可执行文件路径
  nuclei_templates: ""       # nuclei 模板目录（留空则使用默认路径 ~/nuclei-templates）
```

## 分布式部署

VulnScope 支持三种运行模式：

| 模式 | 启动参数 | 包含组件 | 适用场景 |
|------|---------|---------|---------|
| all | `-mode=all` | API + Worker | 开发/小规模单机部署 |
| server | `-mode=server` | 仅 API | 生产环境，水平扩展API |
| worker | `-mode=worker` | 仅 Worker | 生产环境，加机器扩容扫描能力 |

```
机器A: ./vulnscope -mode=server    (API，轻量，处理HTTP请求)
机器B: ./vulnscope -mode=worker    (Worker，重计算，执行扫描)
机器C: ./vulnscope -mode=worker    (Worker，重计算，执行扫描)
       ↕ 都连同一个 Redis + MySQL
```

加 Worker 节点不需要改任何配置，只要能连上 Redis 和 MySQL 即可。

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/targets | 添加扫描目标 |
| POST | /api/targets/import | 批量导入目标 |
| GET | /api/targets | 目标列表 |
| GET | /api/targets/:id | 目标详情 |
| DELETE | /api/targets/:id | 删除目标 |
| POST | /api/tasks | 创建扫描任务 |
| GET | /api/tasks | 任务列表 |
| GET | /api/tasks/:id | 任务详情 |
| DELETE | /api/tasks/:id | 删除任务 |
| GET | /api/tasks/:id/logs | 任务日志 |
| GET | /api/assets | 资产列表 |
| GET | /api/assets/:id | 资产详情 |
| GET | /api/assets/:id/ports | 资产端口 |
| GET | /api/assets/:id/fingers | 资产指纹 |
| GET | /api/vulns | 漏洞列表 |
| GET | /api/vulns/:id | 漏洞详情 |
| PUT | /api/vulns/:id/status | 更新漏洞状态 |
| POST | /api/templates/sync | 同步Nuclei模板 |
| GET | /api/templates/sync/progress | 同步进度 |
| POST | /api/templates/import/repo | 从仓库导入模板 |
| POST | /api/templates/import/dir | 从目录导入模板 |

## 项目结构

```
VulnScope/
├── cmd/scanner/          # 程序入口
├── internal/
│   ├── config/           # 配置加载
│   ├── model/            # 数据模型
│   ├── store/            # 数据库操作 + 模板匹配
│   ├── scheduler/        # 任务调度
│   ├── worker/           # 任务执行
│   │   └── scanner/      # 扫描器封装(nmap/nuclei)
│   └── server/           # HTTP API
│       └── handler/      # 请求处理
├── web/                  # Vue 前端
│   └── src/
│       ├── api/          # API 调用
│       ├── views/        # 页面组件
│       └── router/       # 路由配置
├── schema.sql            # 数据库建表语句
├── config.yaml           # 配置文件
├── go.mod
└── go.sum
```

## 注意事项

- Redis 和 MySQL 必须先于扫描器启动
- Worker 执行扫描需要 nmap 和 nuclei 在 PATH 中，或在 config.yaml 指定路径
- 首次使用需通过 `/api/templates/sync` 接口同步 Nuclei 模板到数据库
- MySQL 需要开启 `mysql-native-password` 认证（8.0+ 默认使用 caching_sha2_password）

## License

MIT
