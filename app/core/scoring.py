"""商用密码应用安全性评估 —— 量化评估（GB/T 39786-2021 四个技术层面）。

模型说明
--------
四个技术层面各占 **25%** 权重（0.25），层面内部按“测评指标权重”加权：

    单元分值 = 该指标下所有适用测评对象分值的算术平均（0~3 分）
    层面得分率 = Σ(单元分值 / 3 × 指标权重) / Σ(指标权重)      （仅统计适用指标）
    层面得分 = 层面得分率 × 100
    总分 = Σ(层面得分率 × 0.25) / Σ(参与计算的层面权重) × 100

分值含义（0~3 分）：0 = 不符合；1 = 部分符合（措施缺失较多）；2 = 基本符合
（措施存在但有缺陷）；3 = 符合；``None`` / ``"NA"`` 表示该指标不适用。

等级判定：总分 ≥ 90 → 符合；70 ≤ 总分 < 90 → 基本符合；< 70 → 不符合。
另外，**任一层面得分率为 0**（该层面所有指标均为 0 分）时直接判定为不符合。
"""
from __future__ import annotations

from .common import ToolError

MAX_ITEM_SCORE = 3
LAYER_WEIGHT = 0.25
PASS_SCORE = 90.0
BASIC_SCORE = 70.0

# 指标权重沿用原站“指标权重”列的三档取值：1.0 / 0.7 / 0.4
LAYERS = [
    {
        "key": "physical",
        "name": "物理和环境安全",
        "objectLabel": "机房",
        "weight": LAYER_WEIGHT,
        "objectPlaceholder": "机房名称",
        "items": [
            {"key": "identity", "name": "身份鉴别", "weight": 1.0,
             "desc": "进入机房人员采用密码技术进行身份鉴别",
             "suggestion": "在机房出入口部署基于 SM2/SM4 的身份鉴别设备（门禁卡、指纹+国密证书），禁用口令直连开门。"},
            {"key": "access_record", "name": "电子门禁记录数据存储完整性", "weight": 0.7,
             "desc": "电子门禁记录数据存储时采用密码技术保证完整性",
             "suggestion": "对门禁记录使用 SM3/HMAC-SM3 生成完整性校验值并随记录一同存储，定期校验。"},
            {"key": "video_record", "name": "视频监控记录数据存储完整性", "weight": 0.7,
             "desc": "视频监控记录数据存储时采用密码技术保证完整性",
             "suggestion": "对录像文件按段计算 SM3 摘要并签名，落盘后定期复核，防止录像被裁剪或替换。"},
        ],
    },
    {
        "key": "network",
        "name": "网络和通信安全",
        "objectLabel": "通道",
        "weight": LAYER_WEIGHT,
        "objectPlaceholder": "通道名称",
        "items": [
            {"key": "identity", "name": "身份鉴别", "weight": 1.0,
             "desc": "通信双方采用密码技术进行身份鉴别",
             "suggestion": "通信前使用 SM2 证书或 SM9 标识完成双向身份鉴别，禁止仅靠 IP/MAC 白名单。"},
            {"key": "data_integrity", "name": "通信数据完整性", "weight": 0.7,
             "desc": "通信过程中数据完整性采用密码技术保证",
             "suggestion": "为通信报文附加 HMAC-SM3 或 SM2 签名，接收端先验签后处理。"},
            {"key": "data_confidentiality", "name": "通信过程中重要数据的机密性", "weight": 1.0,
             "desc": "通信过程中重要数据采用密码技术保证机密性",
             "suggestion": "使用 SM4-GCM 或 TLCP 通道加密，禁用明文传输与自研弱加密。"},
            {"key": "boundary_access", "name": "网络边界访问控制信息的完整性", "weight": 0.7,
             "desc": "网络边界访问控制信息采用密码技术保证完整性",
             "suggestion": "对防火墙/网关的访问控制策略做 SM3 完整性基线，策略变更需签名并审计。"},
            {"key": "access_auth", "name": "安全接入认证", "weight": 0.7,
             "desc": "远程接入设备采用密码技术进行安全接入认证",
             "suggestion": "采用基于数字证书的 IPSec/SSL VPN 接入，并绑定设备指纹。"},
        ],
    },
    {
        "key": "device",
        "name": "设备和计算安全",
        "objectLabel": "设备",
        "weight": LAYER_WEIGHT,
        "objectPlaceholder": "设备名称",
        "items": [
            {"key": "identity", "name": "身份鉴别", "weight": 1.0,
             "desc": "登录设备用户采用密码技术进行身份鉴别",
             "suggestion": "操作系统/数据库管理员登录改用国密 UKey 证书认证，关闭口令直登。"},
            {"key": "log_integrity", "name": "日志记录完整性", "weight": 0.7,
             "desc": "设备日志记录采用密码技术保证完整性",
             "suggestion": "日志集中采集后按批次 SM3 摘要并上链或签名存证，防止篡改。"},
            {"key": "resource_access", "name": "系统资源访问控制信息完整性", "weight": 0.7,
             "desc": "系统资源的访问控制信息采用密码技术保证完整性",
             "suggestion": "对 sudoers、ACL、角色配置等文件做完整性度量（SM3 基线 + 定期校验）。"},
            {"key": "remote_admin", "name": "远程管理通道安全", "weight": 1.0,
             "desc": "远程管理设备时建立安全的密码通道",
             "suggestion": "远程运维统一走国密 SSL 堡垒机，禁用 Telnet/明文 SNMP。"},
            {"key": "resource_mark", "name": "重要信息资源安全标记完整性", "weight": 0.7,
             "desc": "重要信息资源的安全标记采用密码技术保证完整性",
             "suggestion": "对文件密级标记做签名保护，标记变更需留痕并验签。"},
            {"key": "executable", "name": "重要可执行程序完整性、重要可执行程序来源真实性", "weight": 1.0,
             "desc": "重要可执行程序加载或执行前采用密码技术校验完整性与来源",
             "suggestion": "对关键二进制做 SM2 代码签名，加载前验签；部署可信启动度量。"},
        ],
    },
    {
        "key": "app",
        "name": "应用和数据安全",
        "objectLabel": "应用",
        "weight": LAYER_WEIGHT,
        "objectPlaceholder": "应用名称",
        "items": [
            {"key": "identity", "name": "身份鉴别", "weight": 1.0,
             "desc": "应用系统用户采用密码技术进行身份鉴别",
             "suggestion": "登录采用 SM2 证书/USBKey 或基于 SM3 的口令加盐派生，并启用双因素。"},
            {"key": "access_control", "name": "访问控制信息完整性", "weight": 0.7,
             "desc": "访问控制信息采用密码技术保证完整性",
             "suggestion": "对权限表、角色配置计算 HMAC-SM3，越权变更可被检测。"},
            {"key": "resource_mark", "name": "重要信息资源标记完整性", "weight": 0.7,
             "desc": "重要信息资源的安全标记采用密码技术保证完整性",
             "suggestion": "数据分级标记与内容绑定签名，导出时校验标记未被篡改。"},
            {"key": "transfer_confidentiality", "name": "重要数据传输机密性", "weight": 1.0,
             "desc": "重要数据传输时采用密码技术保证机密性",
             "suggestion": "接口层使用 SM4-GCM 字段级加密或 TLCP 通道，密钥由 KMS 下发。"},
            {"key": "storage_confidentiality", "name": "重要数据存储机密性", "weight": 1.0,
             "desc": "重要数据存储时采用密码技术保证机密性",
             "suggestion": "敏感字段落库前 SM4-CBC/GCM 加密，密钥与数据分离存放。"},
            {"key": "transfer_integrity", "name": "重要数据传输完整性", "weight": 1.0,
             "desc": "重要数据传输时采用密码技术保证完整性",
             "suggestion": "报文附带 HMAC-SM3 或 SM2 签名，接收端强校验并拒绝重放。"},
            {"key": "storage_integrity", "name": "重要数据存储完整性", "weight": 1.0,
             "desc": "重要数据存储时采用密码技术保证完整性",
             "suggestion": "对关键表增加 SM3 校验列，读写时校验，异常即告警。"},
            {"key": "non_repudiation", "name": "不可否认性", "weight": 1.0,
             "desc": "重要操作采用密码技术保证不可否认性",
             "suggestion": "关键业务操作使用 SM2 签名并加盖可信时间戳，签名私钥存放于 UKey/HSM。"},
        ],
    },
]

# 二级系统不涉及的指标（依据原站二级指标集合裁剪）
GRADE2_ITEMS = {
    "physical": ["identity", "access_record"],
    "network": ["identity", "data_integrity", "data_confidentiality", "boundary_access"],
    "device": ["identity", "resource_access", "log_integrity"],
    "app": ["identity", "access_control", "transfer_confidentiality",
            "storage_confidentiality", "transfer_integrity", "storage_integrity"],
}

GRADE_LABELS = {2: "二级", 3: "三级", 4: "四级"}

LAYER_BY_KEY = {layer["key"]: layer for layer in LAYERS}
LAYER_NAME_MAP = {layer["name"]: layer["key"] for layer in LAYERS}
LAYER_NAME_MAP.update({layer["key"]: layer["key"] for layer in LAYERS})

SCORE_LABELS = {0: "不符合", 1: "部分符合", 2: "基本符合", 3: "符合"}

DEFAULT_OBJECTS = [
    {"layer": "physical", "name": "机房1",
     "scores": {"identity": 3, "access_record": 3, "video_record": 2}},
    {"layer": "network", "name": "通道1",
     "scores": {"identity": 3, "data_integrity": 3, "data_confidentiality": 2,
                "boundary_access": 3, "access_auth": 2}},
    {"layer": "device", "name": "应用服务器",
     "scores": {"identity": 3, "log_integrity": 2, "resource_access": 3,
                "remote_admin": 3, "resource_mark": 2, "executable": 2}},
    {"layer": "app", "name": "应用1",
     "scores": {"identity": 3, "access_control": 3, "resource_mark": 2,
                "transfer_confidentiality": 3, "storage_confidentiality": 3,
                "transfer_integrity": 3, "storage_integrity": 2,
                "non_repudiation": 2}},
]


def _items_for(layer: dict, grade: int) -> list[dict]:
    if grade == 2:
        allowed = GRADE2_ITEMS[layer["key"]]
        return [it for it in layer["items"] if it["key"] in allowed]
    return list(layer["items"])


def model(grade: int = 3) -> dict:
    """返回量化评估的指标模型（供前端渲染可编辑表格）。"""
    grade = _normalize_grade(grade)
    layers = []
    for layer in LAYERS:
        items = _items_for(layer, grade)
        layers.append({
            "key": layer["key"],
            "name": layer["name"],
            "objectLabel": layer["objectLabel"],
            "objectPlaceholder": layer["objectPlaceholder"],
            "weight": layer["weight"],
            "items": [
                {"key": it["key"], "name": it["name"], "weight": it["weight"],
                 "desc": it["desc"], "suggestion": it["suggestion"]}
                for it in items
            ],
        })
    return {
        "grade": grade,
        "gradeLabel": GRADE_LABELS[grade],
        "grades": [{"value": k, "label": v} for k, v in GRADE_LABELS.items()],
        "layers": layers,
        "scoreScale": [{"value": 0, "label": "0 分（不符合）"},
                       {"value": 1, "label": "1 分（部分符合）"},
                       {"value": 2, "label": "2 分（基本符合）"},
                       {"value": 3, "label": "3 分（符合）"},
                       {"value": None, "label": "不适用"}],
        "thresholds": {"pass": PASS_SCORE, "basic": BASIC_SCORE},
        "maxScore": 100,
        "standard": "GB/T 39786-2021《信息安全技术 信息系统密码应用基本要求》",
    }


def _normalize_grade(grade) -> int:
    if grade in (None, ""):
        return 3
    try:
        value = int(grade)
    except (TypeError, ValueError):
        raise ToolError("系统等级必须是二级(2)、三级(3)或四级(4)")
    if value not in GRADE_LABELS:
        raise ToolError("系统等级必须是二级(2)、三级(3)或四级(4)")
    return value


def _normalize_score(value, layer_name: str, item_name: str, target: str):
    if value is None or (isinstance(value, str) and value.strip().upper() in ("", "NA", "N/A", "NONE", "不适用")):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        raise ToolError(f"{layer_name}/{item_name}（{target}）的分值必须为 0~3 的数字或“不适用”")
    if score != int(score):
        raise ToolError(f"{layer_name}/{item_name}（{target}）的分值必须为 0、1、2、3 或“不适用”")
    score = int(score)
    if score < 0 or score > MAX_ITEM_SCORE:
        raise ToolError(f"{layer_name}/{item_name}（{target}）的分值超出 0~3 范围")
    return score


def evaluate(payload: dict) -> dict:
    """按四个技术层面计算量化评估总分、等级与整改建议。"""
    payload = payload or {}
    grade = _normalize_grade(payload.get("grade"))
    objects = payload.get("objects")
    if not objects or not isinstance(objects, list):
        raise ToolError("请至少添加一个测评对象（机房 / 通道 / 设备 / 应用）")

    layer_results = []
    details = []
    suggestions = []

    for layer in LAYERS:
        items = _items_for(layer, grade)
        item_keys = [it["key"] for it in items]
        layer_objects = []
        for obj in objects:
            if not isinstance(obj, dict):
                raise ToolError("测评对象格式非法，应为包含 layer、name、scores 的对象")
            raw_layer = obj.get("layer")
            layer_key = LAYER_NAME_MAP.get(raw_layer) or LAYER_NAME_MAP.get(str(raw_layer or "").strip())
            if layer_key is None:
                raise ToolError(f"未知的层面：{raw_layer}（应为物理和环境安全/网络和通信安全/设备和计算安全/应用和数据安全）")
            if layer_key != layer["key"]:
                continue
            name = (obj.get("name") or "").strip()
            if not name:
                raise ToolError(f"{layer['name']}层面存在未命名的测评对象")
            scores = obj.get("scores") or {}
            if not isinstance(scores, dict):
                raise ToolError(f"测评对象“{name}”的分值格式非法")
            clean = {}
            for key in item_keys:
                clean[key] = _normalize_score(scores.get(key), layer["name"],
                                              next(it["name"] for it in items if it["key"] == key), name)
            layer_objects.append({"name": name, "scores": clean})

        item_results = []
        weighted_sum = 0.0
        weight_total = 0.0
        applicable_items = 0
        for item in items:
            values = [o["scores"][item["key"]] for o in layer_objects
                      if o["scores"][item["key"]] is not None]
            if not values:
                item_results.append({
                    "key": item["key"],
                    "name": item["name"],
                    "weight": item["weight"],
                    "applicable": False,
                    "unitScore": None,
                    "ratio": None,
                    "weighted": None,
                    "label": "不适用",
                    "objects": [{"name": o["name"], "score": o["scores"][item["key"]]}
                                for o in layer_objects],
                })
                continue
            unit = sum(values) / len(values)
            ratio = unit / MAX_ITEM_SCORE
            weighted_sum += ratio * item["weight"]
            weight_total += item["weight"]
            applicable_items += 1
            item_results.append({
                "key": item["key"],
                "name": item["name"],
                "weight": item["weight"],
                "applicable": True,
                "unitScore": round(unit, 4),
                "ratio": round(ratio, 4),
                "weighted": round(ratio * item["weight"], 4),
                "label": SCORE_LABELS.get(int(round(unit)), "部分符合"),
                "objects": [{"name": o["name"], "score": o["scores"][item["key"]]}
                            for o in layer_objects],
            })
            for o in layer_objects:
                score = o["scores"][item["key"]]
                if score is None:
                    continue
                details.append({
                    "layer": layer["name"],
                    "item": item["name"],
                    "object": o["name"],
                    "score": score,
                    "label": SCORE_LABELS[score],
                    "weight": item["weight"],
                })
                if score < MAX_ITEM_SCORE:
                    suggestions.append({
                        "layer": layer["name"],
                        "item": item["name"],
                        "object": o["name"],
                        "score": score,
                        "level": "高" if score <= 1 else "中",
                        "text": item["suggestion"],
                    })

        ratio = (weighted_sum / weight_total) if weight_total else None
        layer_results.append({
            "key": layer["key"],
            "name": layer["name"],
            "weight": layer["weight"],
            "objectLabel": layer["objectLabel"],
            "objects": [o["name"] for o in layer_objects],
            "objectCount": len(layer_objects),
            "itemCount": len(items),
            "applicableItems": applicable_items,
            "ratio": None if ratio is None else round(ratio, 4),
            "score": None if ratio is None else round(ratio * 100, 2),
            "items": item_results,
        })

    active = [l for l in layer_results if l["ratio"] is not None]
    if not active:
        raise ToolError("所有指标都被标记为“不适用”，无法计算总分，请至少填写一个指标分值")

    weight_sum = sum(l["weight"] for l in active)
    total = sum(l["ratio"] * l["weight"] for l in active) / weight_sum * 100
    total = round(total, 2)

    zero_layers = [l["name"] for l in active if l["ratio"] == 0]
    if zero_layers:
        grade_text = "不符合"
        reason = "、".join(zero_layers) + " 层面得分为 0，直接判定为不符合"
    elif total >= PASS_SCORE:
        grade_text = "符合"
        reason = f"总分 {total} 分 ≥ {PASS_SCORE:.0f} 分"
    elif total >= BASIC_SCORE:
        grade_text = "基本符合"
        reason = f"{BASIC_SCORE:.0f} ≤ 总分 {total} 分 < {PASS_SCORE:.0f} 分"
    else:
        grade_text = "不符合"
        reason = f"总分 {total} 分 < {BASIC_SCORE:.0f} 分"

    suggestions.sort(key=lambda s: (s["score"], s["layer"]))
    return {
        "total": total,
        "grade": grade_text,
        "gradeReason": reason,
        "gradeLevel": grade,
        "gradeLabel": GRADE_LABELS[grade],
        "thresholds": {"pass": PASS_SCORE, "basic": BASIC_SCORE},
        "maxScore": 100,
        "layers": layer_results,
        "details": details,
        "suggestions": suggestions,
        "stats": {
            "objects": len(objects),
            "layers": len(layer_results),
            "applicableLayers": len(active),
            "items": sum(l["itemCount"] for l in layer_results),
            "applicableItems": sum(l["applicableItems"] for l in layer_results),
            "notApplicableItems": sum(l["itemCount"] - l["applicableItems"] for l in layer_results),
            "nonCompliantObjects": len({(d["layer"], d["item"], d["object"])
                                        for d in details if d["score"] == 0}),
        },
        "standard": "GB/T 39786-2021",
    }


__all__ = [
    "LAYERS", "GRADE_LABELS", "SCORE_LABELS", "DEFAULT_OBJECTS",
    "MAX_ITEM_SCORE", "LAYER_WEIGHT", "PASS_SCORE", "BASIC_SCORE",
    "model", "evaluate",
]
