"""商用密码应用安全性评估 —— 量化评估（《商用密码应用安全性评估量化评估规则》2023 版）。

规则实现要点
------------
* 8 个安全层面：1 物理和环境安全、2 网络和通信安全、3 设备和计算安全、4 应用和数据安全
  （密码应用技术要求，层面权重 wi = 10/20/10/30，合计 70）；5 管理制度、6 人员管理、
  7 建设运行、8 应急处置（密码应用管理要求，层面权重 wi = 8/8/8/6，合计 30）。
* 测评对象分值 Si,j,k（表1）：符合 1；符合但不合规 0.5Ra；符合但密钥管理有问题 0.5Rk；
  符合但合规性与密钥管理均有问题 0.25RaRk；不符合 0；不适用不参与计算。
* Ra（表2）：安全强度 <80 比特 0.2；80≤强度<112 比特 0.5；≥112 比特 1。
* Rk（表3）：第一/二级 1；第三级使用一级密码模块且满足 GM/T 0115 5.5 其他要求 1.2，否则 1；
  第四级使用二级密码模块且满足其他要求 1.5，否则 1。
* 弥补：A 弥补 B 时，B 的分值修正为 MAX(0.5×PA, PB)。
* 测评单元 Si,j = 单元内适用测评对象分值的算术平均值（4 位小数）。
* 安全层面 Si = Σwi,j·Si,j / Σwi,j（仅统计适用测评单元，4 位小数）。
* 总分 S = Σ(wi·Si)[1..4]/Σwi[1..4]×70 + Σ(wi·Si)[5..8]/Σwi[5..8]×30（2 位小数）。
* 阈值 60 分（《商用密码应用安全性评估报告模板（2023 版）》）。
"""
from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP

from .common import ToolError

GRADES = {1: "第一级", 2: "第二级", 3: "第三级", 4: "第四级"}
DEFAULT_GRADE = 3

TECH_WEIGHT = 70
MANAGE_WEIGHT = 30
THRESHOLD = 60.0

# 表1 符合情况 -> 分值表达式
STATUSES = [
    {"key": "full", "label": "符合", "desc": "密码使用有效、算法/技术合规、密钥管理安全", "expr": "1"},
    {"key": "partial_compliance", "label": "部分符合（合规性问题）",
     "desc": "密码使用有效、密钥管理安全，但算法/技术不合规", "expr": "0.5Ra"},
    {"key": "partial_key", "label": "部分符合（密钥管理问题）",
     "desc": "密码使用有效、算法/技术合规，但密钥管理存在问题", "expr": "0.5Rk"},
    {"key": "partial_both", "label": "部分符合（合规性+密钥管理）",
     "desc": "密码使用有效，但算法/技术不合规且密钥管理也有问题", "expr": "0.25RaRk"},
    {"key": "none", "label": "不符合", "desc": "未使用密码技术，或未正确有效使用导致安全需求未满足", "expr": "0"},
    {"key": "na", "label": "不适用", "desc": "该测评指标不适用，不参与量化评估", "expr": None},
]
STATUS_MAP = {s["key"]: s for s in STATUSES}

MANAGE_STATUSES = [
    {"key": "full", "label": "符合", "score": 1.0},
    {"key": "partial", "label": "部分符合", "score": 0.5},
    {"key": "none", "label": "不符合", "score": 0.0},
    {"key": "na", "label": "不适用", "score": None},
]
MANAGE_SCORE = {s["key"]: s["score"] for s in MANAGE_STATUSES}

# 表2 密码算法/技术合规性修正参数 Ra
RA_OPTIONS = [
    {"value": 0.2, "label": "安全强度 < 80 比特（与安全要求不匹配）"},
    {"value": 0.5, "label": "80 ≤ 安全强度 < 112 比特（一定程度上可提供保障）"},
    {"value": 1.0, "label": "安全强度 ≥ 112 比特（可较好提供保障）"},
]
RA_VALUES = [o["value"] for o in RA_OPTIONS]

# 表3 使用的密码模块级别（用于推导 Rk，仅第三/四级影响取值）
MODULE_LEVELS = [
    {"value": 0, "label": "未使用/不满足 GM/T 0115 5.5 其他要求"},
    {"value": 1, "label": "一级密码模块且满足其他要求"},
    {"value": 2, "label": "二级密码模块且满足其他要求"},
    {"value": 3, "label": "三级密码模块且满足其他要求"},
]


def rk_of(grade: int, module_level=None) -> float:
    """表3：密钥管理安全修正参数 Rk。"""
    grade = int(grade)
    try:
        module_level = int(module_level) if module_level not in (None, "") else 0
    except (TypeError, ValueError):
        module_level = 0
    if grade in (1, 2):
        return 1.0
    if grade == 3:
        return 1.2 if module_level == 1 else 1.0
    if grade == 4:
        return 1.5 if module_level == 2 else 1.0
    return 1.0


def r4(value: float) -> float:
    """四舍五入保留 4 位小数。"""
    return float(Decimal(str(value)).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP))


def r2(value: float) -> float:
    """四舍五入保留 2 位小数。"""
    return float(Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _w(g1, g2, g3, g4) -> dict:
    """按密码应用级别取权重；None 表示该等级下该测评指标不适用。"""
    return {1: g1, 2: g2, 3: g3, 4: g4}


LAYERS = [
    {
        "index": 1, "key": "physical", "name": "物理和环境安全", "weight": 10, "kind": "tech",
        "target": "机房",
        "units": [
            {"key": "identity", "name": "身份鉴别", "weights": _w(0.4, 0.7, 1, 1),
             "suggestion": "在机房出入口部署基于 SM2 证书 / SM4 卡的身份鉴别装置，禁用口令直连开门。"},
            {"key": "door_record", "name": "电子门禁记录数据存储完整性", "weights": _w(0.4, 0.4, 0.7, 0.7),
             "suggestion": "对门禁记录逐条计算 HMAC-SM3 校验值并随记录存储，定期复核。"},
            {"key": "video_record", "name": "视频记录数据存储完整性", "weights": _w(None, None, 0.7, 0.7),
             "suggestion": "录像分段计算 SM3 摘要并签名存证，防止录像被裁剪或替换。"},
        ],
    },
    {
        "index": 2, "key": "network", "name": "网络和通信安全", "weight": 20, "kind": "tech",
        "target": "通道",
        "units": [
            {"key": "identity", "name": "身份鉴别", "weights": _w(0.4, 0.7, 1, 1),
             "suggestion": "通信双方使用 SM2 证书或 SM9 标识完成双向身份鉴别，禁止仅依赖 IP/MAC 白名单。"},
            {"key": "comm_integrity", "name": "通信数据完整性", "weights": _w(0.4, 0.4, 0.7, 1),
             "suggestion": "报文附加 HMAC-SM3 或 SM2 签名，接收端先验签后处理。"},
            {"key": "comm_confidentiality", "name": "通信过程中重要数据的机密性", "weights": _w(0.4, 0.7, 1, 1),
             "suggestion": "使用 SM4-GCM 或 TLCP 通道加密，禁用明文传输与自研弱加密。"},
            {"key": "boundary_acl", "name": "网络边界访问控制信息的完整性", "weights": _w(0.4, 0.4, 0.4, 0.7),
             "suggestion": "对防火墙/网关策略做 SM3 完整性基线，策略变更需签名并审计。"},
            {"key": "access_auth", "name": "安全接入认证", "weights": _w(None, None, 0.4, 0.7),
             "suggestion": "远程接入采用基于数字证书的 IPSec/SSL VPN，并绑定设备指纹。"},
        ],
    },
    {
        "index": 3, "key": "device", "name": "设备和计算安全", "weight": 10, "kind": "tech",
        "target": "设备",
        "units": [
            {"key": "identity", "name": "身份鉴别", "weights": _w(0.4, 0.7, 1, 1),
             "suggestion": "操作系统/数据库管理员登录改用国密 UKey 证书认证，关闭口令直登。"},
            {"key": "remote_admin", "name": "远程管理通道安全", "weights": _w(None, None, 1, 1),
             "suggestion": "远程运维统一走国密 SSL 堡垒机，禁用 Telnet/明文 SNMP。"},
            {"key": "resource_acl", "name": "系统资源访问控制信息完整性", "weights": _w(0.4, 0.4, 0.4, 0.7),
             "suggestion": "对 sudoers、ACL、角色配置做完整性度量（SM3 基线 + 定期校验）。"},
            {"key": "resource_mark", "name": "重要信息资源安全标记完整性", "weights": _w(None, None, 0.4, 0.7),
             "suggestion": "安全标记与内容绑定签名，标记变更留痕并验签。"},
            {"key": "log_integrity", "name": "日志记录完整性", "weights": _w(0.4, 0.4, 0.4, 0.7),
             "suggestion": "日志集中采集后按批次 SM3 摘要并签名存证，防止篡改。"},
            {"key": "executable", "name": "重要可执行程序完整性、重要可执行程序来源真实性",
             "weights": _w(None, None, 0.7, 1),
             "suggestion": "关键二进制做 SM2 代码签名，加载前验签并做可信启动度量。"},
        ],
    },
    {
        "index": 4, "key": "app", "name": "应用和数据安全", "weight": 30, "kind": "tech",
        "target": "应用",
        "units": [
            {"key": "identity", "name": "身份鉴别", "weights": _w(0.4, 0.7, 1, 1),
             "suggestion": "登录采用 SM2 证书/UKey 或基于 SM3 的口令加盐派生，并启用双因素。"},
            {"key": "access_acl", "name": "访问控制信息完整性", "weights": _w(0.4, 0.4, 0.4, 0.7),
             "suggestion": "对权限表、角色配置计算 HMAC-SM3，越权变更可被检测。"},
            {"key": "resource_mark", "name": "重要信息资源安全标记完整性", "weights": _w(None, None, 0.4, 0.7),
             "suggestion": "数据分级标记与内容绑定签名，导出时校验标记未被篡改。"},
            {"key": "transfer_confidentiality", "name": "重要数据传输机密性", "weights": _w(0.4, 0.7, 1, 1),
             "suggestion": "接口层使用 SM4-GCM 字段级加密或 TLCP 通道，密钥由 KMS 下发。"},
            {"key": "storage_confidentiality", "name": "重要数据存储机密性", "weights": _w(0.4, 0.7, 1, 1),
             "suggestion": "敏感字段落库前 SM4-CBC/GCM 加密，密钥与数据分离存放。"},
            {"key": "transfer_integrity", "name": "重要数据传输完整性", "weights": _w(0.4, 0.7, 0.7, 1),
             "suggestion": "传输报文附加 HMAC-SM3/SM2 签名，接收端验签后才入库。"},
            {"key": "storage_integrity", "name": "重要数据存储完整性", "weights": _w(0.4, 0.7, 0.7, 1),
             "suggestion": "存储数据计算完整性校验值并定期复核，异常时告警。"},
            {"key": "non_repudiation", "name": "不可否认性", "weights": _w(None, None, 1, 1),
             "suggestion": "关键业务操作使用 SM2 签名并留存可信时间戳，支持事后仲裁。"},
        ],
    },
    {
        "index": 5, "key": "manage_policy", "name": "管理制度", "weight": 8, "kind": "manage",
        "target": "制度",
        "units": [
            {"key": "policy", "name": "具备密码应用安全管理制度", "weights": _w(1, 1, 1, 1),
             "suggestion": "发布覆盖密码应用全生命周期的安全管理制度，明确责任与流程。"},
            {"key": "key_rule", "name": "密钥管理规则", "weights": _w(0.7, 0.7, 0.7, 0.7),
             "suggestion": "制定密钥生成、分发、存储、更新、销毁规则，明确密钥分级与保护要求。"},
            {"key": "operation", "name": "建立操作规程", "weights": _w(None, 0.7, 0.7, 0.7),
             "suggestion": "针对密码设备、密钥管理等岗位编制可执行的操作规程。"},
            {"key": "review", "name": "定期修订安全管理制度", "weights": _w(None, None, 0.7, 0.7),
             "suggestion": "每年至少一次评审并修订密码安全管理制度，留存修订记录。"},
            {"key": "release", "name": "明确管理制度发布流程", "weights": _w(None, None, 0.7, 0.7),
             "suggestion": "明确制度起草、审核、批准、发布、归档流程与责任人。"},
            {"key": "record", "name": "制度执行过程记录留存", "weights": _w(None, None, 0.7, 0.7),
             "suggestion": "留存制度执行记录（含密码操作日志），保存期限不少于 6 个月。"},
        ],
    },
    {
        "index": 6, "key": "manage_people", "name": "人员管理", "weight": 8, "kind": "manage",
        "target": "人员",
        "units": [
            {"key": "law", "name": "了解并遵守密码相关法律法规和密码管理制度",
             "weights": _w(0.7, 0.7, 0.7, 0.7),
             "suggestion": "组织密码法律法规与制度宣贯，留存培训与考核记录。"},
            {"key": "duty", "name": "建立密码应用岗位责任制度", "weights": _w(None, 1, 1, 1),
             "suggestion": "明确密码管理、密钥管理、安全审计等岗位职责并落实到人。"},
            {"key": "training", "name": "建立上岗人员培训制度", "weights": _w(None, 0.7, 0.7, 0.7),
             "suggestion": "密码相关岗位人员上岗前接受培训并考核合格。"},
            {"key": "assessment", "name": "定期进行安全岗位人员考核", "weights": _w(None, None, 0.7, 0.7),
             "suggestion": "定期对密码相关岗位人员进行技能与合规考核。"},
            {"key": "confidential", "name": "建立关键岗位人员保密制度和调离制度",
             "weights": _w(0.7, 0.7, 0.7, 0.7),
             "suggestion": "签署保密协议，人员调离时收回密钥、权限与设备。"},
        ],
    },
    {
        "index": 7, "key": "manage_build", "name": "建设运行", "weight": 8, "kind": "manage",
        "target": "建设",
        "units": [
            {"key": "scheme", "name": "制定密码应用方案", "weights": _w(1, 1, 1, 1),
             "suggestion": "编制密码应用方案并通过评审，覆盖各安全层面的密码需求。"},
            {"key": "key_strategy", "name": "制定密钥安全管理策略", "weights": _w(1, 1, 1, 1),
             "suggestion": "明确密钥全生命周期管理策略及密码模块等级要求。"},
            {"key": "implement", "name": "制定实施方案", "weights": _w(0.7, 0.7, 0.7, 0.7),
             "suggestion": "依据密码应用方案编制实施方案并落实责任与进度。"},
            {"key": "pre_eval", "name": "投入运行前进行密码应用安全性评估", "weights": _w(1, 1, 1, 1),
             "suggestion": "系统上线前完成密评并整改，形成评估报告。"},
            {"key": "periodic_eval", "name": "定期开展密码应用安全性评估及攻防对抗演习",
             "weights": _w(None, None, 0.7, 0.7),
             "suggestion": "按规定周期开展密评与攻防演练，跟踪整改闭环。"},
        ],
    },
    {
        "index": 8, "key": "manage_emergency", "name": "应急处置", "weight": 6, "kind": "manage",
        "target": "应急",
        "units": [
            {"key": "strategy", "name": "应急策略", "weights": _w(1, 1, 1, 1),
             "suggestion": "制定密码应用应急策略与预案，明确触发条件与处置流程。"},
            {"key": "handle", "name": "事件处置", "weights": _w(None, None, 0.7, 0.7),
             "suggestion": "建立密码安全事件处置流程，定期演练并留存记录。"},
            {"key": "report", "name": "向有关主管部门上报处置情况", "weights": _w(None, None, 0.7, 0.7),
             "suggestion": "重大密码安全事件按规定时限向主管部门报告处置情况。"},
        ],
    },
]

LAYER_MAP = {layer["key"]: layer for layer in LAYERS}
UNIT_MAP = {(layer["key"], unit["key"]): unit for layer in LAYERS for unit in layer["units"]}

TECH_WEIGHT_SUM = sum(layer["weight"] for layer in LAYERS if layer["kind"] == "tech")
MANAGE_WEIGHT_SUM = sum(layer["weight"] for layer in LAYERS if layer["kind"] == "manage")


def grade_of(value) -> int:
    """归一化密码应用级别（1~4）。"""
    if value in (None, ""):
        return DEFAULT_GRADE
    try:
        grade = int(value)
    except (TypeError, ValueError):
        raise ToolError(f"不支持的密码应用级别：{value}")
    if grade not in GRADES:
        raise ToolError(f"不支持的密码应用级别：{value}（仅支持第一级~第四级）")
    return grade


def units_of(layer: dict, grade: int) -> list:
    """按等级裁剪：权重为“/”的测评单元在该等级下不适用。"""
    return [unit for unit in layer["units"] if unit["weights"][grade] is not None]


def model(grade=None) -> dict:
    """返回指标模型（按密码应用级别裁剪），供前端渲染可编辑表格。"""
    grade = grade_of(grade)
    layers = []
    for layer in LAYERS:
        layers.append({
            "index": layer["index"],
            "key": layer["key"],
            "name": layer["name"],
            "kind": layer["kind"],
            "weight": layer["weight"],
            "target": layer["target"],
            "units": [
                {"key": unit["key"], "name": unit["name"],
                 "weight": unit["weights"][grade], "suggestion": unit["suggestion"]}
                for unit in units_of(layer, grade)
            ],
        })
    return {
        "grade": grade,
        "gradeLabel": GRADES[grade],
        "grades": [{"value": g, "label": label} for g, label in GRADES.items()],
        "layers": layers,
        "statuses": STATUSES,
        "manageStatuses": MANAGE_STATUSES,
        "raOptions": RA_OPTIONS,
        "moduleLevels": MODULE_LEVELS,
        "threshold": THRESHOLD,
        "groupWeights": {"tech": TECH_WEIGHT, "manage": MANAGE_WEIGHT},
        "techWeightSum": TECH_WEIGHT_SUM,
        "manageWeightSum": MANAGE_WEIGHT_SUM,
        "standard": "《商用密码应用安全性评估量化评估规则》(2023版)",
    }


def default_targets(layer: dict) -> list:
    """各技术层面的默认测评对象（与原站示例口径一致）。"""
    if layer["kind"] == "manage":
        return []
    return {
        "physical": ["机房1"],
        "network": ["通道1"],
        "device": ["应用服务器", "数据库"],
        "app": ["应用1"],
    }[layer["key"]]


def default_rows(grade=None) -> list:
    """默认测评对象与判定结果（示例数据，供页面初始化）。"""
    grade = grade_of(grade)
    rows = []
    for layer in LAYERS:
        units = units_of(layer, grade)
        if layer["kind"] == "manage":
            for idx, unit in enumerate(units):
                rows.append({"layer": layer["key"], "unit": unit["key"], "target": layer["target"],
                             "status": "partial" if idx == 1 else "full"})
            continue
        for name in default_targets(layer):
            for idx, unit in enumerate(units):
                if idx % 4 == 2:
                    status = "partial_compliance"
                elif idx % 5 == 3:
                    status = "partial_key"
                else:
                    status = "full"
                rows.append({"layer": layer["key"], "unit": unit["key"], "target": name, "status": status})
    return rows


def _num(value, name: str, low: float, high: float) -> float:
    try:
        num = float(value)
    except (TypeError, ValueError):
        raise ToolError(f"{name}取值非法：{value}")
    if num < low or num > high:
        raise ToolError(f"{name}超出取值范围 [{low}, {high}]：{value}")
    return num


def status_score(row: dict, layer: dict, ra: float, rk: float):
    """表1：单个测评对象的分值（None 表示不适用）。"""
    key = (row.get("status") or "full").strip()
    if layer["kind"] == "manage":
        if key not in MANAGE_SCORE:
            raise ToolError(f"不支持的管理判定结果：{key}")
        return MANAGE_SCORE[key]
    if key not in STATUS_MAP:
        raise ToolError(f"不支持的符合情况：{key}")
    if key == "full":
        return 1.0
    if key == "none":
        return 0.0
    if key == "na":
        return None
    if key == "partial_compliance":
        return r4(0.5 * ra)
    if key == "partial_key":
        return r4(0.5 * rk)
    return r4(0.25 * ra * rk)


def _status_label(layer: dict, key: str) -> str:
    table = MANAGE_STATUSES if layer["kind"] == "manage" else STATUSES
    return next((s["label"] for s in table if s["key"] == key), key)


def evaluate(payload: dict) -> dict:
    """按 2023 版量化评估规则计算总分、结论、层面得分、明细与整改建议。"""
    payload = payload or {}
    grade = grade_of(payload.get("grade"))
    ra = _num(payload.get("ra", 1), "密码算法/技术安全强度修正参数 Ra", 0.2, 1)
    if ra not in RA_VALUES:
        raise ToolError("Ra 仅可取 0.2 / 0.5 / 1")
    rk = rk_of(grade, payload.get("moduleLevel"))

    rows = payload.get("rows")
    if rows is None and isinstance(payload.get("objects"), list):
        rows = payload["objects"]
    if not isinstance(rows, list) or not rows:
        raise ToolError("请提供测评对象数据（rows）")

    entries = []
    for raw in rows:
        if not isinstance(raw, dict):
            raise ToolError("rows 中每个元素必须是对象")
        layer = LAYER_MAP.get((raw.get("layer") or "").strip())
        if not layer:
            raise ToolError(f"未知的安全层面：{raw.get('layer')}")
        unit = UNIT_MAP.get((layer["key"], (raw.get("unit") or "").strip()))
        if not unit:
            raise ToolError(f"未知的测评单元：{layer['name']}/{raw.get('unit')}")
        target = (raw.get("target") or layer["target"]).strip()
        score = status_score(raw, layer, ra, rk)
        entries.append({
            "layer": layer, "unit": unit, "layerKey": layer["key"], "unitKey": unit["key"],
            "target": target, "weight": unit["weights"][grade], "score": score,
            "rawScore": score, "status": (raw.get("status") or "full").strip(),
            "compensate": (raw.get("compensate") or "").strip() or None,
        })

    # 弥补：B 被同单元内的 A 弥补时，B = MAX(0.5×PA, PB)
    compensations = []
    for entry in entries:
        donor_name = entry["compensate"]
        if not donor_name:
            continue
        donor = next((e for e in entries
                      if e["layerKey"] == entry["layerKey"] and e["unitKey"] == entry["unitKey"]
                      and e["target"] == donor_name and e is not entry), None)
        if donor is None:
            raise ToolError("弥补对象不存在：%s / %s / %s"
                            % (entry["layer"]["name"], entry["unit"]["name"], donor_name))
        if donor["rawScore"] is None:
            continue
        base = entry["rawScore"] or 0.0
        fixed = max(r4(0.5 * donor["rawScore"]), base)
        if entry["rawScore"] is None or fixed > base:
            compensations.append({
                "layer": entry["layer"]["name"], "unit": entry["unit"]["name"],
                "target": entry["target"], "donor": donor["target"],
                "before": entry["rawScore"], "after": fixed,
            })
        entry["score"] = fixed

    # 测评单元 = 适用对象算术平均；层面 = Σw·S/Σw
    unit_scores = {}
    details = []
    for entry in entries:
        unit_id = (entry["layerKey"], entry["unitKey"])
        bucket = unit_scores.setdefault(unit_id, {"unit": entry["unit"], "weight": entry["weight"], "values": []})
        if entry["score"] is not None:
            bucket["values"].append(entry["score"])
        if entry["weight"] is None:
            continue
        details.append({
            "layer": entry["layer"]["name"],
            "unit": entry["unit"]["name"],
            "object": entry["target"],
            "status": _status_label(entry["layer"], entry["status"]),
            "score": None if entry["score"] is None else r4(entry["score"]),
            "weight": entry["weight"],
            "compensatedBy": entry["compensate"] or "",
        })

    layers_out = []
    tech_num = tech_den = manage_num = manage_den = 0.0
    for layer in LAYERS:
        applicable = []
        for unit in layer["units"]:
            bucket = unit_scores.get((layer["key"], unit["key"]))
            if not bucket or bucket["weight"] is None or not bucket["values"]:
                continue
            applicable.append({
                "key": unit["key"], "name": unit["name"], "weight": bucket["weight"],
                "score": r4(sum(bucket["values"]) / len(bucket["values"])),
                "count": len(bucket["values"]),
            })
        score = None
        if applicable:
            wsum = sum(u["weight"] for u in applicable)
            score = r4(sum(u["weight"] * u["score"] for u in applicable) / wsum)
            if layer["kind"] == "tech":
                tech_num += layer["weight"] * score
                tech_den += layer["weight"]
            else:
                manage_num += layer["weight"] * score
                manage_den += layer["weight"]
        layers_out.append({
            "index": layer["index"], "key": layer["key"], "name": layer["name"],
            "kind": layer["kind"], "weight": layer["weight"], "score": score,
            "units": applicable,
        })

    if tech_den == 0 and manage_den == 0:
        raise ToolError("没有任何适用的测评指标，无法计算总分")

    if tech_den and manage_den:
        total = tech_num / tech_den * TECH_WEIGHT + manage_num / manage_den * MANAGE_WEIGHT
    elif tech_den:
        total = tech_num / tech_den * 100
    else:
        total = manage_num / manage_den * 100
    total = r2(total)

    passed = total >= THRESHOLD
    return {
        "projectName": (payload.get("projectName") or "某信息系统密码应用量化评估").strip(),
        "grade": grade,
        "gradeLabel": GRADES[grade],
        "standard": "《商用密码应用安全性评估量化评估规则》(2023版)",
        "ra": ra,
        "rk": rk,
        "moduleLevel": payload.get("moduleLevel"),
        "total": total,
        "maxScore": 100,
        "threshold": THRESHOLD,
        "conclusion": "通过" if passed else "不通过",
        "gradeReason": "总分 %s 分%s 60 分阈值" % (total, "不低于" if passed else "低于"),
        "techScore": None if not tech_den else r4(tech_num / tech_den * 100),
        "manageScore": None if not manage_den else r4(manage_num / manage_den * 100),
        "techWeight": TECH_WEIGHT,
        "manageWeight": MANAGE_WEIGHT,
        "layers": layers_out,
        "details": details,
        "compensations": compensations,
        "suggestions": _suggestions(rows),
    }


def _suggestions(rows: list) -> list:
    out = []
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        layer = LAYER_MAP.get((raw.get("layer") or "").strip())
        if not layer:
            continue
        unit = UNIT_MAP.get((layer["key"], (raw.get("unit") or "").strip()))
        if not unit:
            continue
        status = (raw.get("status") or "full").strip()
        if status in ("full", "na"):
            continue
        out.append({
            "level": "高" if status == "none" else ("中" if status.startswith("partial") else "低"),
            "layer": layer["name"],
            "item": unit["name"],
            "object": raw.get("target") or layer["target"],
            "status": _status_label(layer, status),
            "text": unit["suggestion"],
        })
    return out


__all__ = [
    "GRADES", "THRESHOLD", "STATUSES", "MANAGE_STATUSES", "RA_OPTIONS", "MODULE_LEVELS",
    "LAYERS", "LAYER_MAP", "UNIT_MAP", "model", "evaluate", "default_rows", "default_targets",
    "grade_of", "rk_of", "units_of",
]
