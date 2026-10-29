"""内置敏感路径字典。值: (命中时的基础严重度, 标题, CTF 利用思路)。"""

PATHS: dict[str, tuple[str, str, str]] = {
    ".git/config": (
        "high",
        "Git 仓库配置文件暴露",
        "使用 git-dumper 还原源码，审计历史提交中的硬编码凭据、flag 与过滤逻辑。",
    ),
    ".git/HEAD": (
        "high",
        "Git 仓库 HEAD 文件暴露",
        "确认 .git 目录可访问后，用 git-dumper 还原整个仓库。",
    ),
    ".svn/entries": (
        "high",
        "SVN 元数据泄露",
        "尝试 svn-dump 或直接访问 .svn 下的原始文件获取源码。",
    ),
    ".env": (
        "critical",
        "环境变量文件 .env 暴露",
        "读取数据库口令、API Key、APP_KEY；Laravel 的 APP_KEY 可进一步伪造会话或反序列化。",
    ),
    ".env.bak": (
        "high",
        ".env 备份文件暴露",
        "尝试读取旧版配置中的数据库与密钥信息。",
    ),
    "web.config": (
        "high",
        "web.config 配置文件暴露",
        "检查连接字符串、认证配置与调试开关。",
    ),
    "WEB-INF/web.xml": (
        "high",
        "WEB-INF 描述符暴露",
        "结合目录穿越读取 classes 与 lib，进一步反编译审计。",
    ),
    "backup.zip": (
        "high",
        "站点备份压缩包暴露",
        "下载后审计源码、数据库导出与隐藏接口。",
    ),
    "www.zip": (
        "high",
        "源码压缩包 www.zip 暴露",
        "解压审计，重点关注上传、反序列化与命令执行入口。",
    ),
    "wwwroot.zip": (
        "high",
        "源码压缩包 wwwroot.zip 暴露",
        "解压审计，寻找未授权接口与硬编码密钥。",
    ),
    "backup.tar.gz": (
        "high",
        "站点备份 tar.gz 暴露",
        "下载解包后审计源码与配置。",
    ),
    "db.sql": (
        "high",
        "数据库导出文件暴露",
        "从 SQL 中提取账号密码哈希、flag 表与业务数据。",
    ),
    "dump.sql": (
        "high",
        "数据库导出文件暴露",
        "从 SQL 中提取账号密码哈希与敏感数据。",
    ),
    "database.sql": (
        "high",
        "数据库导出文件暴露",
        "检索 INSERT 语句中的凭据与 flag。",
    ),
    "phpinfo.php": (
        "medium",
        "phpinfo 调试页面暴露",
        "泄露绝对路径、disable_functions、上传临时目录，为 LFI/RCE 提供关键信息。",
    ),
    "info.php": (
        "medium",
        "PHP 信息页面暴露",
        "获取配置与路径信息，辅助后续利用。",
    ),
    "test.php": (
        "low",
        "测试用 PHP 页面暴露",
        "检查页面功能是否包含调试、上传或命令执行。",
    ),
    "adminer.php": (
        "medium",
        "Adminer 数据库管理入口暴露",
        "尝试默认或弱口令登录数据库。",
    ),
    "phpmyadmin/": (
        "medium",
        "phpMyAdmin 入口暴露",
        "尝试弱口令登录，登录后可尝试写入 webshell。",
    ),
    "pma/": (
        "medium",
        "phpMyAdmin 入口暴露",
        "尝试弱口令登录数据库管理面板。",
    ),
    "admin/": (
        "low",
        "后台管理目录暴露",
        "枚举后台登录入口，尝试弱口令、默认口令与越权。",
    ),
    "login/": (
        "low",
        "登录入口暴露",
        "检查验证码、锁定策略与默认账号，必要时做低频弱口令测试。",
    ),
    "manager/html": (
        "high",
        "Tomcat Manager 入口暴露",
        "尝试 tomcat/tomcat 等默认口令，登录后可部署 WAR 获取权限。",
    ),
    "host-manager/html": (
        "medium",
        "Tomcat Host Manager 入口暴露",
        "尝试默认口令登录管理面板。",
    ),
    "actuator": (
        "medium",
        "Spring Boot Actuator 端点暴露",
        "访问 /actuator/env、/actuator/heapdump 获取配置与内存中的凭据。",
    ),
    "actuator/env": (
        "high",
        "Actuator 环境配置暴露",
        "检索 spring.datasource、secret、password 等敏感属性。",
    ),
    "actuator/heapdump": (
        "critical",
        "Actuator heapdump 可下载",
        "下载堆转储后用 JDumpSpider / MAT 提取明文密码与 session。",
    ),
    "swagger-ui.html": (
        "medium",
        "Swagger 接口文档暴露",
        "枚举未授权 API，重点测试用户信息、文件上传与命令执行类接口。",
    ),
    "swagger-ui/": (
        "medium",
        "Swagger 接口文档暴露",
        "读取 /v3/api-docs 获取完整接口清单。",
    ),
    "v2/api-docs": (
        "medium",
        "Swagger v2 接口文档暴露",
        "从 JSON 中提取全部接口并测试未授权访问。",
    ),
    "v3/api-docs": (
        "medium",
        "OpenAPI 接口文档暴露",
        "从 JSON 中提取全部接口并测试未授权访问。",
    ),
    "api/": (
        "low",
        "API 路径暴露",
        "结合文档或 JS 中的接口列表测试未授权与越权。",
    ),
    "graphql": (
        "medium",
        "GraphQL 端点暴露",
        "尝试 introspection 查询获取 schema，再测试未授权字段。",
    ),
    "console/": (
        "high",
        "H2 Console 暴露",
        "尝试 JDBC URL 注入或默认口令，可能导致 RCE。",
    ),
    "druid/index.html": (
        "medium",
        "Druid 监控面板暴露",
        "查看连接池、SQL 监控与会话信息，寻找敏感数据。",
    ),
    "nacos/": (
        "medium",
        "Nacos 控制台暴露",
        "尝试 nacos/nacos 默认口令，登录后查看配置中的密钥。",
    ),
    "server-status": (
        "low",
        "Apache server-status 暴露",
        "查看当前请求与客户端信息，辅助信息收集。",
    ),
    "server-info": (
        "low",
        "Apache server-info 暴露",
        "获取模块与配置信息。",
    ),
    "robots.txt": (
        "info",
        "robots.txt 可访问",
        "其中 Disallow 的路径往往指向后台、备份或隐藏接口。",
    ),
    "sitemap.xml": (
        "info",
        "sitemap.xml 可访问",
        "从站点地图中发现隐藏页面与接口。",
    ),
    "crossdomain.xml": (
        "info",
        "crossdomain.xml 可访问",
        "若允许任意域，可结合跨域读取测试。",
    ),
    "flag": (
        "high",
        "疑似 flag 文件可直接访问",
        "直接读取并确认内容是否符合 flag 格式。",
    ),
    "flag.txt": (
        "high",
        "疑似 flag 文本文件可直接访问",
        "直接读取并确认内容是否符合 flag 格式。",
    ),
    "flag.php": (
        "high",
        "疑似 flag PHP 文件可直接访问",
        "访问页面查看输出；如无输出可尝试源码泄露或 LFI。",
    ),
    "upload/": (
        "low",
        "上传目录暴露",
        "检查目录是否可浏览，尝试上传绕过与文件名解析技巧。",
    ),
    "uploads/": (
        "low",
        "上传目录暴露",
        "浏览已上传文件，寻找 webshell 或敏感资料。",
    ),
    "files/": (
        "low",
        "文件目录暴露",
        "浏览目录清单，寻找备份、源码或 flag。",
    ),
    ".DS_Store": (
        "low",
        ".DS_Store 文件泄露",
        "解析目录结构，发现隐藏文件与上传文件名。",
    ),
    "README.md": (
        "info",
        "README 文件暴露",
        "阅读部署说明，可能包含默认账号、路径与版本信息。",
    ),
    "readme.md": (
        "info",
        "README 文件暴露",
        "阅读部署说明，可能包含默认账号与路径信息。",
    ),
    "composer.json": (
        "low",
        "composer.json 暴露",
        "根据依赖版本寻找已知漏洞组件。",
    ),
    "package.json": (
        "low",
        "package.json 暴露",
        "根据依赖版本寻找已知漏洞组件与内部包名。",
    ),
    ".well-known/security.txt": (
        "info",
        "security.txt 可访问",
        "获取安全联系人信息，确认测试范围。",
    ),
    "login.php": (
        "low",
        "PHP 登录入口暴露",
        "尝试默认口令与 SQL 注入。",
    ),
    "admin.php": (
        "low",
        "PHP 后台入口暴露",
        "尝试默认口令、弱口令与参数越权。",
    ),
    "upload.php": (
        "medium",
        "上传接口暴露",
        "测试文件类型校验、内容检测与解析路径绕过。",
    ),
    "api.php": (
        "low",
        "API 入口暴露",
        "枚举 action 参数，测试未授权调用。",
    ),
    "config.php": (
        "high",
        "PHP 配置文件暴露",
        "读取数据库凭据；若为空输出可结合 LFI 读取源码。",
    ),
    "config.php.bak": (
        "critical",
        "PHP 配置文件备份暴露",
        "读取数据库口令与密钥，进一步登录数据库或伪造会话。",
    ),
    "wp-config.php.bak": (
        "critical",
        "WordPress 配置备份暴露",
        "读取数据库凭据与认证密钥。",
    ),
    "www-data/": (
        "low",
        "疑似 Web 根目录备份",
        "浏览目录获取源码与配置。",
    ),
}

# 请求这些路径时保留响应片段，便于报告展示证据
SNIPPET_PATHS = {
    ".git/config",
    ".env",
    ".env.bak",
    "config.php",
    "config.php.bak",
    "wp-config.php.bak",
    "robots.txt",
    "README.md",
    "readme.md",
    "flag",
    "flag.txt",
    "flag.php",
}
