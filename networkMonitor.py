try:
    import platform
    import os
    import sys
    from scapy.all import *
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP, TCP, UDP
    from collections import defaultdict

    import datetime
    import threading
    import sqlite3
    import time
    import socket
    import logging
    from prettytable import PrettyTable
    import signal
    import json
except ImportError as e:
    print(f"导入模块失败: {e}")
    print("请确保已安装所需模块：pip install scapy prettytable")
    sys.exit(1)

# 全局配置
DEFAULT_CONFIG = {
    'database_file': 'network_monitor.db',
    'log_file': 'network_monitor.log',
    'report_interval': 60,
    'max_domain_length': 50,
    'debug_mode': False,
    'backup_interval': 3600,  # 每小时备份一次
    'max_records': 1000000,  # 最大记录数
    'cleanup_threshold': 900000  # 清理阈值
}


class ConfigManager:
    @staticmethod
    def load_config(config_file='config.json'):
        """加载配置文件"""
        config = DEFAULT_CONFIG.copy()
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config.update(json.load(f))
        except Exception as e:
            print(f"加载配置文件失败: {e}")
        return config

    @staticmethod
    def save_config(config, config_file='config.json'):
        """保存配置文件"""
        try:
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"保存配置文件失败: {e}")


class SystemInfo:
    """系统信息类"""

    @staticmethod
    def get_os_type():
        """获取操作系统类型"""
        try:
            return sys.platform.lower()
        except:
            return "unknown"

    @staticmethod
    def is_admin():
        """检查是否具有管理员权限"""
        try:
            if SystemInfo.get_os_type() == 'windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False

    @staticmethod
    def get_network_interfaces():
        """获取网络接口列表"""
        try:
            if SystemInfo.get_os_type() == 'windows':
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                return [iface['name'] for iface in interfaces if iface.get('status') == 'Up']
            else:
                return [iface for iface in get_if_list() if iface != 'lo']
        except Exception as e:
            print(f"获取网络接口列表失败: {e}")
            return []


class DatabaseManager:
    def __init__(self, db_file):
        self.db_file = db_file
        self.conn = None
        self.cursor = None
        self.lock = threading.Lock()
        self.setup_database()
        # 确保数据库目录存在
        try:
            db_dir = os.path.dirname(db_file)
            if not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                print(f"Created database directory: {db_dir}")

            # 直接尝试创建/连接数据库
            self.setup_database()

        except Exception as e:
            print(f"Database initialization error: {str(e)}")
            print(f"Database path: {db_file}")
            print(f"Current working directory: {os.getcwd()}")
            raise

    def setup_database(self):
        """初始化数据库"""
        try:
            print(f"Attempting to connect/create database at: {self.db_file}")

            # 确保连接是新的
            if self.conn:
                self.conn.close()

            # 创建新连接
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
            self.cursor = self.conn.cursor()

            # 设置一些数据库参数
            self.conn.execute("PRAGMA journal_mode=WAL")  # 使用WAL模式提高性能
            self.conn.execute("PRAGMA synchronous=NORMAL")  # 适当降低同步级别提高性能

            print("Creating tables if they don't exist...")

            # 创建域名访问表
            self.cursor.execute('''
                    CREATE TABLE IF NOT EXISTS domain_access (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        ip_address TEXT NOT NULL,
                        packet_size INTEGER,
                        protocol TEXT,
                        os_type TEXT,
                        interface TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    ''')

            # 创建HTTP请求表
            self.cursor.execute('''
                    CREATE TABLE IF NOT EXISTS http_requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        protocol TEXT,
                        request_type TEXT,
                        src_ip TEXT,
                        src_port INTEGER,
                        dst_ip TEXT,
                        dst_port INTEGER,
                        host TEXT,
                        url TEXT,
                        request_body TEXT,
                        packet_size INTEGER,
                        os_type TEXT,
                        interface TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    ''')

            # 创建索引
            print("Creating indexes...")
            indexes = [
                ('idx_domain', 'domain_access(domain)'),
                ('idx_timestamp', 'domain_access(timestamp)'),
                ('idx_ip_address', 'domain_access(ip_address)'),
                ('idx_http_timestamp', 'http_requests(timestamp)'),
                ('idx_http_host', 'http_requests(host)'),
                ('idx_http_protocol', 'http_requests(protocol)')
            ]

            for index_name, index_cols in indexes:
                try:
                    self.cursor.execute(f'CREATE INDEX IF NOT EXISTS {index_name} ON {index_cols}')
                except sqlite3.OperationalError as e:
                    print(f"创建索引失败 {index_name}: {e}")

            self.conn.commit()

            # 验证数据库是否正确创建
            self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = self.cursor.fetchall()
            print(f"验证数据库表: {tables}")

            print("Database initialization completed successfully")

            # 测试插入
            self.test_database_access()

        except sqlite3.Error as e:
            print(f"SQLite error during setup: {e}")
            print(f"Database file: {self.db_file}")
            raise
        except Exception as e:
            print(f"Unexpected error during database setup: {e}")
            raise

    def test_database_access(self):
        """测试数据库访问"""
        try:
            # 测试插入
            test_data = ('test.com', '1.1.1.1', 100, 'DNS', 'windows', 'eth0')
            self.insert_record(test_data)

            # 测试查询
            self.cursor.execute("SELECT * FROM domain_access WHERE domain='test.com'")
            result = self.cursor.fetchone()

            if result:
                print("Database test insert/query successful")
                # 清理测试数据
                self.cursor.execute("DELETE FROM domain_access WHERE domain='test.com'")
                self.conn.commit()
            else:
                print("Warning: Test insert appeared to fail")

        except Exception as e:
            print(f"Database test access failed: {e}")

    def insert_http_record(self, data):
        """插入HTTP请求记录"""
        with self.lock:
            try:
                self.cursor.execute('''
                INSERT INTO http_requests 
                (protocol, request_type, src_ip, src_port, dst_ip, dst_port, 
                 host, url, request_body, packet_size, os_type, interface)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', data)
                self.conn.commit()
            except sqlite3.Error as e:
                print(f"插入HTTP记录失败: {e}")

    def get_http_statistics(self):
        """获取HTTP统计数据"""
        with self.lock:
            try:
                self.cursor.execute('''
                SELECT 
                    host,
                    protocol,
                    COUNT(*) as count,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    GROUP_CONCAT(DISTINCT request_type) as request_types
                FROM http_requests
                WHERE host IS NOT NULL
                GROUP BY host, protocol
                ORDER BY count DESC
                LIMIT 10
                ''')
                return self.cursor.fetchall()
            except sqlite3.Error as e:
                print(f"获取HTTP统计数据失败: {e}")
                return []

    def insert_record(self, data):
        """插入记录"""
        with self.lock:
            try:
                self.cursor.execute('''
                INSERT INTO domain_access 
                (domain, timestamp, ip_address, packet_size, protocol, os_type, interface)
                VALUES (?, datetime('now', 'localtime'), ?, ?, ?, ?, ?)
                ''', data)
                self.conn.commit()
            except sqlite3.Error as e:
                print(f"插入记录失败: {e}")

    def get_statistics(self):
        """获取统计数据"""
        with self.lock:
            try:
                self.cursor.execute('''
                SELECT domain, COUNT(*) as count, 
                       MIN(timestamp) as first_seen,
                       MAX(timestamp) as last_seen,
                       GROUP_CONCAT(DISTINCT ip_address) as ip_addresses
                FROM domain_access
                GROUP BY domain
                ORDER BY count DESC
                LIMIT 10
                ''')
                return self.cursor.fetchall()
            except sqlite3.Error as e:
                print(f"获取统计数据失败: {e}")
                return []

    def backup_database(self):
        """备份数据库"""
        try:
            backup_file = f"{self.db_file}.backup_{int(time.time())}"
            with self.lock:
                with open(backup_file, 'wb') as f:
                    for line in self.conn.iterdump():
                        f.write(f'{line}\n'.encode('utf-8'))
            return True
        except Exception as e:
            print(f"备份数据库失败: {e}")
            return False

    def cleanup_old_records(self, max_records):
        """清理旧记录"""
        try:
            with self.lock:
                self.cursor.execute('SELECT COUNT(*) FROM domain_access')
                count = self.cursor.fetchone()[0]
                if count > max_records:
                    self.cursor.execute('''
                    DELETE FROM domain_access 
                    WHERE id IN (
                        SELECT id FROM domain_access 
                        ORDER BY timestamp ASC 
                        LIMIT ?
                    )
                    ''', (count - max_records,))
                    self.conn.commit()
        except sqlite3.Error as e:
            print(f"清理记录失败: {e}")

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()


class NetworkMonitor:
    def __init__(self, config=None):
        self.config = DEFAULT_CONFIG.copy()
        if config:
            self.config.update(config)

        self.os_type = SystemInfo.get_os_type()
        self.check_privileges()

        # 初始化数据结构
        self.domain_stats = defaultdict(lambda: {
            'count': 0,
            'first_seen': None,
            'last_seen': None,
            'ip_addresses': set()
        })

        self.lock = threading.Lock()
        self.running = True

        # 设置工作目录和日志
        self.setup_working_directory()
        self.setup_logging()

        # 初始化数据库
        self.db = DatabaseManager(self.config['database_file'])

        # 启动维护线程
        self.start_maintenance_thread()

    def check_privileges(self):
        """检查权限"""
        if not SystemInfo.is_admin():
            print("警告: 程序需要管理员/root权限才能正常运行")
            if self.os_type == 'windows':
                print("请以管理员身份运行此程序")
            else:
                print("请使用sudo运行此程序")
            sys.exit(1)

    def get_default_interface(self):
        """获取默认网络接口"""
        interfaces = SystemInfo.get_network_interfaces()
        return interfaces[0] if interfaces else None

    def generate_report(self):
        """生成报告"""
        while self.running:
            try:
                # DNS统计
                dns_stats = self.db.get_statistics()
                if dns_stats:
                    table = PrettyTable()
                    table.field_names = ["域名", "访问次数", "首次访问", "最后访问", "IP地址"]

                    for domain, count, first_seen, last_seen, ip_addresses in dns_stats:
                        table.add_row([
                            domain[:self.config['max_domain_length']],
                            count,
                            first_seen,
                            last_seen,
                            ip_addresses[:50] + "..." if len(ip_addresses) > 50 else ip_addresses
                        ])

                    print("\n" + "=" * 80)
                    print("DNS查询统计报告")
                    print(f"生成时间: {datetime.datetime.now()}")
                    print("=" * 80)
                    print(table)

                # HTTP统计
                http_stats = self.db.get_http_statistics()
                if http_stats:
                    http_table = PrettyTable()
                    http_table.field_names = ["主机名", "协议", "请求数", "首次请求", "最后请求", "请求类型"]

                    for host, protocol, count, first_seen, last_seen, req_types in http_stats:
                        http_table.add_row([
                            host[:self.config['max_domain_length']],
                            protocol,
                            count,
                            first_seen,
                            last_seen,
                            req_types
                        ])

                    print("\nHTTP/HTTPS请求统计报告")
                    print("=" * 80)
                    print(http_table)
                    print("=" * 80 + "\n")

            except Exception as e:
                self.logger.error(f"生成报告失败: {e}")

            time.sleep(self.config['report_interval'])

    def setup_working_directory(self):
        """设置工作目录"""
        try:
            if self.os_type == 'windows':
                base_dir = os.path.join(os.getenv('APPDATA'), 'NetworkMonitor')
            elif self.os_type  == 'darwin':
                base_dir = os.path.join(os.path.expanduser('~'), 'work', 'tmp','networkmonitor')
            else:
                base_dir = os.path.join('/var', 'log', 'networkmonitor')
                if not os.access(base_dir, os.W_OK):
                    base_dir = os.path.join(os.path.expanduser('~'), '.networkmonitor')

            os.makedirs(base_dir, exist_ok=True)
            self.base_dir = base_dir

            # 更新文件路径
            self.config['database_file'] = os.path.join(base_dir, 'network_monitor.db')
            self.config['log_file'] = os.path.join(base_dir, 'network_monitor.log')
        except Exception as e:
            print(f"设置工作目录失败: {e}")
            sys.exit(1)

    def setup_logging(self):
        """配置日志"""
        try:
            log_format = '%(asctime)s - %(levelname)s - %(message)s'
            logging.basicConfig(
                level=logging.DEBUG if self.config['debug_mode'] else logging.INFO,
                format=log_format,
                handlers=[
                    logging.FileHandler(self.config['log_file']),
                    logging.StreamHandler()
                ]
            )
            self.logger = logging.getLogger(__name__)
            self.logger.info(f"操作系统: {self.os_type}")
            self.logger.info(f"工作目录: {self.base_dir}")
        except Exception as e:
            print(f"设置日志失败: {e}")
            sys.exit(1)

    def start_maintenance_thread(self):
        """启动维护线程"""

        def maintenance_task():
            while self.running:
                try:
                    # 备份数据库
                    self.db.backup_database()
                    # 清理旧记录
                    self.db.cleanup_old_records(self.config['max_records'])
                    time.sleep(self.config['backup_interval'])
                except Exception as e:
                    self.logger.error(f"维护任务失败: {e}")
                    time.sleep(60)

        thread = threading.Thread(target=maintenance_task)
        thread.daemon = True
        thread.start()

    def packet_callback(self, packet):
        """数据包回调处理"""
        try:
            current_time = datetime.datetime.now()

            # DNS 查询监控
            if packet.haslayer(DNS) and packet.haslayer(IP):
                if packet[DNS].qr == 0:  # DNS query
                    try:
                        domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                    except:
                        domain = str(packet[DNS].qd.qname).rstrip('.')

                    ip_src = packet[IP].src
                    packet_size = len(packet)
                    interface = packet.sniffed_on if hasattr(packet, 'sniffed_on') else None

                    with self.lock:
                        stats = self.domain_stats[domain]
                        if stats['first_seen'] is None:
                            stats['first_seen'] = current_time
                        stats['count'] += 1
                        stats['last_seen'] = current_time
                        stats['ip_addresses'].add(ip_src)

                    # 保存到数据库
                    self.db.insert_record((domain, ip_src, packet_size, 'DNS',
                                           self.os_type, interface))

                    # 打印 DNS 信息
                    print(f"\n\033[92m[{current_time}] DNS查询:\033[0m")
                    print(f"\033[94m域名:\033[0m {domain}")
                    print(f"\033[94m源IP:\033[0m {ip_src}")
                    print(f"\033[94m接口:\033[0m {interface}")
                    print(f"\033[94m大小:\033[0m {packet_size} bytes")

            # HTTP/HTTPS 请求监控
            if packet.haslayer(IP) and packet.haslayer(TCP):
                try:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport

                    # HTTP(80)或HTTPS(443)流量
                    if dst_port in [80, 443] or src_port in [80, 443]:
                        protocol = "HTTPS" if (dst_port == 443 or src_port == 443) else "HTTP"
                        packet_size = len(packet)

                        # 构建请求信息字典
                        request_info = {
                            "basic_info": {
                                "protocol": protocol,
                                "src_ip": src_ip,
                                "src_port": src_port,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "packet_size": packet_size,
                                "timestamp": datetime.datetime.now().isoformat()
                            },
                            "headers": {},
                            "request": {
                                "method": "",
                                "url": "",
                                "version": "",
                                "body": ""
                            }
                        }

                        # 提取负载数据
                        if packet.haslayer(Raw):
                            try:
                                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                                # 解析HTTP请求行
                                lines = payload.split('\r\n')
                                if lines:
                                    # 解析请求行
                                    req_line = lines[0].split(' ')
                                    if len(req_line) >= 3:
                                        request_info["request"]["method"] = req_line[0]
                                        request_info["request"]["url"] = req_line[1]
                                        request_info["request"]["version"] = req_line[2]

                                    # 解析请求头
                                    for line in lines[1:]:
                                        if not line or line == '\r\n':
                                            break
                                        if ':' in line:
                                            key, value = line.split(':', 1)
                                            request_info["headers"][key.strip()] = value.strip()

                                    # 提取请求体
                                    body_start = payload.find('\r\n\r\n')
                                    if body_start != -1:
                                        request_info["request"]["body"] = payload[body_start + 4:1000]  # 限制长度

                            except Exception as e:
                                self.logger.error(f"解析payload失败: {e}")
                                request_info["error"] = str(e)

                        # 转换为JSON字符串
                        request_body_json = json.dumps(request_info, ensure_ascii=False)

                        # 保存到数据库
                        http_data = (
                            protocol,
                            request_info["request"]["method"],
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            request_info["headers"].get("Host", ""),
                            request_info["request"]["url"],
                            request_body_json,  # JSON字符串
                            packet_size,
                            self.os_type,
                            packet.sniffed_on if hasattr(packet, 'sniffed_on') else None
                        )
                        self.db.insert_http_record(http_data)

                        # 打印信息
                        print(f"\n\033[93m[{datetime.datetime.now()}] {protocol} 请求:\033[0m")
                        print(f"\033[95m方法:\033[0m {request_info['request']['method']}")
                        print(f"\033[95m源IP:\033[0m {src_ip}:{src_port}")
                        print(f"\033[95m目标IP:\033[0m {dst_ip}:{dst_port}")
                        if request_info["headers"].get("Host"):
                            print(f"\033[95m主机名:\033[0m {request_info['headers']['Host']}")
                        print(f"\033[95mURL:\033[0m {request_info['request']['url']}")
                        print(f"\033[95m大小:\033[0m {packet_size} bytes")
                except Exception as e:
                    self.logger.error(f"处理HTTP请求包错误: {e}")
        except Exception as e:
            self.logger.error(f"处理数据包错误: {e}")

    def start_capture(self, interface=None):
        """开始捕获"""
        try:
            if not interface:
                interface = self.get_default_interface()

            if not interface:
                self.logger.error("未找到可用网络接口")
                return

            self.logger.info(f"开始在接口 {interface} 上捕获流量")

            # 设置过滤器：DNS + HTTP + HTTPS
            filter_rule = "udp port 53 or tcp port 80 or tcp port 443"

            sniff(iface=interface,
                  filter=filter_rule,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: not self.running)

        except Exception as e:
            self.logger.error(f"捕获错误: {e}")
            raise

    def cleanup(self):
        """清理资源"""
        try:
            self.running = False
            if hasattr(self, 'db'):
                self.db.close()
            self.logger.info("监控已停止，资源已清理")
        except Exception as e:
            print(f"清理资源错误: {e}")


def signal_handler(signum, frame):
    """信号处理函数"""
    print("\n接收到退出信号，正在清理...")
    if 'monitor' in globals():
        monitor.cleanup()
    sys.exit(0)


def main():
    # 声明全局变量
    global monitor

    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # 加载配置
    config = ConfigManager.load_config()

    monitor = None
    try:

        monitor = NetworkMonitor(config)
        # 显示可用接口
        interfaces = SystemInfo.get_network_interfaces()
        if not interfaces:
            print("未找到可用网络接口")
            return

        print("\n可用网络接口:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")

        # 用户选择接口
        choice = input("\n请选择网络接口编号 (直接回车使用默认接口): ").strip()
        interface = None
        if choice:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    interface = interfaces[idx]
                else:
                    print("无效选择，使用默认接口")
            except ValueError:
                print("无效输入，使用默认接口")

        # 创建报告线程
        report_thread = threading.Thread(target=monitor.generate_report)
        report_thread.daemon = True
        report_thread.start()

        # 开始捕获
        print(f"\n开始监控网络流量 (按 Ctrl+C 停止)...")
        monitor.start_capture(interface)

    except KeyboardInterrupt:
        print("\n正在停止监控...")
    except Exception as e:
        print(f"发生错误: {e}")
    finally:
        if monitor:
            monitor.cleanup()


if __name__ == "__main__":
    main()
