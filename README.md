# behavior-log-risk-analyzer-v2

上网行为日志威胁初筛工具 V2。

## 项目定位
这是一个基于真实安全运营场景抽象出的脱敏 Demo 工具，
用于演示如何将日志初筛、IOC 关联、异常行为规则检测与结构化报告输出做成可复用流程。

本项目定位为：
- 辅助人工复核
- 方法验证型 Demo
- 安全运营 / 风险分析 / 威胁情报方向项目展示

不定位为：
- 替代最终人工研判
- 直接作为生产环境自动告警系统

## Demo Output

工具运行后会生成两类结果：

- `results.csv`：逐条日志的命中情况、规则结果、风险等级
- `report.md`：汇总统计、IOC 命中、规则命中、高风险样本、复核建议

示例摘要：

- Loaded 5 log rows
- IOC hits: 0
- Rule hits: 4
- High risk: 0
- Medium risk: 4

---

## 快速开始

安装依赖：

```bash
pip install -r requirements.txt
```

## V2 的关键升级

- 支持 **CSV / XLSX** 日志输入
- 支持 **自动识别表头**，不再依赖固定表头
- 支持 **手动覆盖列名**，遇到特殊日志也能跑
- **IOC 文件可选**，不传 IOC 也能只跑规则引擎
- 规则引擎不只做 IOC 对比，还支持：
  - 非工作时间访问
  - HTTP 明文访问
  - 可执行/压缩文件下载
  - 同源 IP 重复访问同一目标
  - 未知终端对外访问
  - 域名/URL 可疑关键词检测
  - 直接访问公网 IP 且无域名上下文
- 自动输出 `results.csv` 和 `report.md`

## 适用场景

- 企业上网行为日志初筛
- IOC 关联分析
- 周报 / 研判报告辅助输出
- 安全运营 / 风险分析 / 威胁情报实习项目展示

## 项目结构

```text
behavior-log-risk-analyzer-v2/
├─ config/
│  ├─ fields.yaml
│  ├─ header_aliases.yaml
│  └─ rules.yaml
├─ data/
│  ├─ sample_logs.csv
│  ├─ sample_logs_alt.csv
│  └─ sample_iocs.xlsx
├─ src/
│  ├─ loader.py
│  ├─ header_mapper.py
│  ├─ normalizer.py
│  ├─ matcher.py
│  ├─ rules_engine.py
│  ├─ scorer.py
│  ├─ reporter.py
│  └─ main.py
├─ requirements.txt
└─ README.md
```

## 安装依赖

```bash
pip install -r requirements.txt
```

## 运行方式

### 1）正常跑：日志 + IOC

```bash
python src/main.py --log data/sample_logs.csv --ioc data/sample_iocs.xlsx
```

### 2）只跑规则，不传 IOC

```bash
python src/main.py --log data/sample_logs.csv
```

### 3）表头不同也能跑（自动识别）

```bash
python src/main.py --log data/sample_logs_alt.csv --ioc data/sample_iocs.xlsx
```

### 4）自动识别失败时，手动指定列名

```bash
python src/main.py \
  --log your_log.csv \
  --ioc your_ioc.xlsx \
  --src-ip-col "source_ip" \
  --dst-ip-col "dest_ip" \
  --time-col "event_time" \
  --detail-col "message"
```

### 5）你的真实文件（示例）

```bash
python src/main.py \
  --log "behavior260326.csv" \
  --ioc "information0312.xlsx" \
  --output-dir output_real
```

## 自动识别逻辑

程序会优先按以下顺序找列：

1. 命令行手动指定
2. `config/fields.yaml` 里的精确字段名
3. `config/header_aliases.yaml` 里的别名词典

如果还是找不到，会报错提示你手动指定。

## 输出结果

运行后默认生成：

- `output/results.csv`
- `output/report.md`

其中：

- `results.csv`：逐行风险结果
- `report.md`：总体统计 + 高风险样本 + 人工复核建议

## 核心边界

- 这是**日志初筛工具**，不是终局判断系统
- 规则命中 ≠ 真正攻击，需要结合白名单、上下文、资产信息人工复核
- GitHub 演示时请只放**脱敏样例**，不要上传真实客户日志、真实 IOC、真实报告


## 安全说明

- 公开仓库仅保留脱敏样例数据。
- 真实日志、真实 IOC、真实报告仅建议在本地私有环境中使用，不进入公开仓库
