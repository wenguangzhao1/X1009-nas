# NAS 监控仪表盘 — 零依赖 NAS 监控系统
基于树莓派 5 + Geekworm X1009 SATA HAT 的 NAS 监控系统。

## 组件

| 文件 | 说明 |
|------|------|
| `nas-monitor.py` | Web 监控仪表盘主程序（纯 Python 标准库，零外部依赖） |
| `nas-monitor.service` | systemd 服务模板 |
| `pi-nas-architecture.html` | NAS 静态架构图 |

## 仪表盘功能

- **系统概览**: 主机名、内核、运行时间、CPU 温度、节流状态
- **内存/Swap**: 使用量、进度条
- **X1009 扩展板**: PCIe 链路、SATA 端口明细、驱动状态、DMA 修复
- **存储使用**: 各挂载点容量、进度条（绿/橙/红三色）
- **磁盘健康 (SMART)**: 模型、序列号、温度、通电时间、关键属性、健康评级
- **告警面板**: 自动检测重分配扇区、CRC 错误、不可校正错误、温度过高
- **访问日志**: HTTP 页面访问记录
- **Samba 文件访问**: 用户连接/断开、文件操作审计

## 快速开始

```bash
# 手动启动
python3 nas-monitor.py

# 安装为系统服务（含 sudoers 配置）
sudo python3 nas-monitor.py --install
```

安装后访问 `http://<NAS-IP>:8080`。

## 技术栈

- Python 标准库 (`http.server` + `subprocess`)，零 pip 依赖
- 嵌入式 HTML/CSS/JS（暗色主题）
- Samba full_audit VFS 模块 + systemd journal 解析
- 15 秒 SMART 数据缓存，30 秒前端自动刷新

## 硬件

- Raspberry Pi 5 (4GB)
- Geekworm X1009 V1.1 PCIe → 5 口 SATA (JMB585)
- 4× SATA HDD (ntfs-3g)
- 12V DC 供电
