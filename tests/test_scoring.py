"""量化评估（《商用密码应用安全性评估量化评估规则》2023 版）。

覆盖：按级别裁剪的指标模型、表1 分值映射（Ra/Rk）、弥补规则、单元算术平均、
层面加权平均、技术要求 70 分 / 管理要求 30 分、60 分阈值与错误路径。
"""
from __future__ import annotations

import pytest

from app.core import scoring
from app.server import create_app


@pytest.fixture()
def client():
    return create_app().test_client()


def ok_data(client, path, payload):
    body = client.post(path, json=payload).get_json()
    assert body["code"] == 0, body
    return body["data"]


def rows_from_model(model, status="full"):
    """按模型生成“所有对象全部同一判定”的 rows（管理层面自动映射为部分符合）。"""
    rows = []
    for layer in model["layers"]:
        layer_status = status
        if layer["kind"] == "manage" and status.startswith("partial"):
            layer_status = "partial"
        if layer["kind"] == "manage":
            for unit in layer["units"]:
                rows.append({"layer": layer["key"], "unit": unit["key"],
                             "target": layer["target"], "status": layer_status})
            continue
        for name in scoring.default_targets(scoring.LAYER_MAP[layer["key"]]):
            for unit in layer["units"]:
                rows.append({"layer": layer["key"], "unit": unit["key"],
                             "target": name, "status": layer_status})
    return rows


def layer_of(data, key):
    return next(layer for layer in data["layers"] if layer["key"] == key)


# ---------------------------------------------------------------------------
# 指标模型（表4 裁剪）
# ---------------------------------------------------------------------------

def test_model_structure(client):
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    assert model["grade"] == 3 and model["gradeLabel"] == "第三级"
    assert [layer["key"] for layer in model["layers"]] == [
        "physical", "network", "device", "app",
        "manage_policy", "manage_people", "manage_build", "manage_emergency",
    ]
    assert [layer["weight"] for layer in model["layers"]] == [10, 20, 10, 30, 8, 8, 8, 6]
    assert model["techWeightSum"] == 70 and model["manageWeightSum"] == 30
    assert model["threshold"] == 60
    counts = [len(layer["units"]) for layer in model["layers"]]
    assert counts == [3, 5, 6, 8, 6, 5, 5, 3]


@pytest.mark.parametrize("grade,tech,manage", [(1, 15, 9), (2, 15, 12), (3, 22, 19), (4, 22, 19)])
def test_model_grade_trim(client, grade, tech, manage):
    model = ok_data(client, "/api/scoring/model", {"grade": grade})
    kinds = {"tech": 0, "manage": 0}
    for layer in model["layers"]:
        kinds[layer["kind"]] += len(layer["units"])
    assert kinds["tech"] == tech and kinds["manage"] == manage


def test_model_grade2_excludes_grade3_units(client):
    model2 = ok_data(client, "/api/scoring/model", {"grade": 2})
    units = {(layer["key"], unit["key"]) for layer in model2["layers"] for unit in layer["units"]}
    assert ("physical", "video_record") not in units
    assert ("network", "access_auth") not in units
    assert ("device", "remote_admin") not in units
    assert ("device", "executable") not in units
    assert ("app", "non_repudiation") not in units
    assert ("manage_policy", "review") not in units
    # 二级下这些指标的权重取自表4 第二级列
    weights = {unit["key"]: unit["weight"]
               for layer in model2["layers"] if layer["key"] == "network" for unit in layer["units"]}
    assert weights["identity"] == 0.7 and weights["comm_integrity"] == 0.4


def test_model_weight_table(client):
    """抽查表4 中的权重取值。"""
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    w = {(layer["key"], unit["key"]): unit["weight"]
         for layer in model["layers"] for unit in layer["units"]}
    assert w[("physical", "identity")] == 1
    assert w[("physical", "door_record")] == 0.7
    assert w[("network", "boundary_acl")] == 0.4
    assert w[("network", "access_auth")] == 0.4
    assert w[("device", "executable")] == 0.7
    assert w[("app", "non_repudiation")] == 1
    assert w[("manage_emergency", "handle")] == 0.7


def test_model_bad_grade(client):
    body = client.post("/api/scoring/model", json={"grade": 5}).get_json()
    assert body["code"] == 1 and "级别" in body["msg"]


def test_default_rows(client):
    data = ok_data(client, "/api/scoring/default", {"grade": 3})
    assert data["grade"] == 3 and len(data["rows"]) > 0
    assert {row["layer"] for row in data["rows"]} == {layer["key"] for layer in scoring.LAYERS}
    # 默认数据可直接用于计算
    result = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": data["rows"]})
    assert 0 <= result["total"] <= 100


# ---------------------------------------------------------------------------
# 表2 / 表3 修正参数
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("grade,module,rk", [
    (1, 0, 1.0), (2, 0, 1.0), (2, 1, 1.0),
    (3, 0, 1.0), (3, 1, 1.2), (3, 2, 1.0),
    (4, 1, 1.0), (4, 2, 1.5),
])
def test_rk_table(grade, module, rk):
    assert scoring.rk_of(grade, module) == rk


def test_status_scores_table1():
    layer = scoring.LAYER_MAP["app"]
    assert scoring.status_score({"status": "full"}, layer, 1, 1.2) == 1.0
    assert scoring.status_score({"status": "none"}, layer, 1, 1.2) == 0.0
    assert scoring.status_score({"status": "na"}, layer, 1, 1.2) is None
    assert scoring.status_score({"status": "partial_compliance"}, layer, 0.5, 1.2) == 0.25
    assert scoring.status_score({"status": "partial_key"}, layer, 0.5, 1.2) == 0.6
    assert scoring.status_score({"status": "partial_both"}, layer, 0.5, 1.2) == 0.15
    manage = scoring.LAYER_MAP["manage_policy"]
    assert scoring.status_score({"status": "full"}, manage, 1, 1) == 1.0
    assert scoring.status_score({"status": "partial"}, manage, 1, 1) == 0.5


# ---------------------------------------------------------------------------
# 计算规则
# ---------------------------------------------------------------------------

def test_all_full_is_100(client):
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows_from_model(model)})
    assert data["total"] == 100.0
    assert data["conclusion"] == "通过"
    assert data["techScore"] == 100.0 and data["manageScore"] == 100.0
    assert all(layer["score"] == 1.0 for layer in data["layers"])
    assert data["suggestions"] == []


def test_all_none_is_zero(client):
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows_from_model(model, "none")})
    assert data["total"] == 0.0
    assert data["conclusion"] == "不通过"


def test_app_layer_zero_gives_70(client):
    """应用和数据安全层面 0 分：技术要求 = (10+20+10)/70×70 = 40，管理 30 → 总分 70。"""
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    rows = rows_from_model(model)
    for row in rows:
        if row["layer"] == "app":
            row["status"] = "none"
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows})
    assert layer_of(data, "app")["score"] == 0.0
    assert data["total"] == pytest.approx(70.0, abs=0.01)


def test_manage_layer_zero_gives_70(client):
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    rows = rows_from_model(model)
    for row in rows:
        if row["layer"].startswith("manage_"):
            row["status"] = "none"
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows})
    assert data["manageScore"] == 0.0
    assert data["total"] == pytest.approx(70.0, abs=0.01)


def test_unit_average_and_layer_weighted(client):
    """单对象场景：单元分值即对象分值；层面分值 = Σw·S/Σw。"""
    rows = [
        {"layer": "physical", "unit": "identity", "target": "机房1", "status": "full"},
        {"layer": "physical", "unit": "door_record", "target": "机房1", "status": "none"},
        {"layer": "physical", "unit": "video_record", "target": "机房1", "status": "partial_compliance"},
        {"layer": "network", "unit": "identity", "target": "通道1", "status": "full"},
        {"layer": "app", "unit": "identity", "target": "应用1", "status": "full"},
        {"layer": "manage_policy", "unit": "policy", "target": "制度", "status": "full"},
    ]
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows, "ra": 0.5})
    physical = layer_of(data, "physical")
    # 0.5Ra = 0.25；层面 = (1×1 + 0.7×0 + 0.7×0.25)/(1+0.7+0.7)
    expected = (1 * 1 + 0.7 * 0 + 0.7 * 0.25) / 2.4
    assert physical["score"] == pytest.approx(round(expected, 4), abs=1e-4)
    units = {unit["key"]: unit for unit in physical["units"]}
    assert units["identity"]["score"] == 1.0
    assert units["video_record"]["score"] == 0.25
    # 技术要求只有物理(10)、网络(20)、应用(30) 三层参与
    assert data["techScore"] == pytest.approx(
        round((10 * physical["score"] + 20 * 1 + 30 * 1) / 60 * 100, 4), abs=1e-3)


def test_multiple_targets_averaged(client):
    rows = [
        {"layer": "physical", "unit": "identity", "target": "机房A", "status": "full"},
        {"layer": "physical", "unit": "identity", "target": "机房B", "status": "none"},
        {"layer": "network", "unit": "identity", "target": "通道1", "status": "full"},
    ]
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows})
    unit = next(u for u in layer_of(data, "physical")["units"] if u["key"] == "identity")
    assert unit["score"] == 0.5 and unit["count"] == 2


def test_not_applicable_excluded(client):
    """整单元不适用时，该单元不参与层面加权。"""
    rows = [
        {"layer": "physical", "unit": "identity", "target": "机房1", "status": "full"},
        {"layer": "physical", "unit": "door_record", "target": "机房1", "status": "na"},
    ]
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows})
    physical = layer_of(data, "physical")
    assert [u["key"] for u in physical["units"]] == ["identity"]
    assert physical["score"] == 1.0


def test_compensation_rule(client):
    """A 弥补 B：B = MAX(0.5×PA, PB)。"""
    rows = [
        {"layer": "physical", "unit": "identity", "target": "机房A", "status": "full"},
        {"layer": "physical", "unit": "identity", "target": "机房B", "status": "none",
         "compensate": "机房A"},
    ]
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows})
    unit = next(u for u in layer_of(data, "physical")["units"] if u["key"] == "identity")
    assert unit["score"] == pytest.approx(0.75, abs=1e-4)
    assert data["compensations"] and data["compensations"][0]["after"] == 0.5
    detail = next(d for d in data["details"] if d["object"] == "机房B")
    assert detail["score"] == 0.5 and detail["compensatedBy"] == "机房A"


def test_partial_manage_and_key_is_50(client):
    """技术要求与管理要求均为 0.5：总分 = 0.5×70 + 0.5×30 = 50 分，未达阈值。"""
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    rows = []
    for layer in model["layers"]:
        status = "partial" if layer["kind"] == "manage" else "partial_key"
        if layer["kind"] == "manage":
            for unit in layer["units"]:
                rows.append({"layer": layer["key"], "unit": unit["key"],
                             "target": layer["target"], "status": status})
        else:
            for name in scoring.default_targets(scoring.LAYER_MAP[layer["key"]]):
                for unit in layer["units"]:
                    rows.append({"layer": layer["key"], "unit": unit["key"],
                                 "target": name, "status": status})
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows,
                                                     "ra": 1, "moduleLevel": 0})
    # Rk = 1（三级未使用一级密码模块）→ 部分符合（密钥管理问题）= 0.5
    assert data["total"] == pytest.approx(50.0, abs=0.01)
    assert data["conclusion"] == "不通过"


def test_rk_affects_total(client):
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    rows = rows_from_model(model, "partial_key")
    low = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows, "moduleLevel": 0})
    high = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "rows": rows, "moduleLevel": 1})
    assert low["rk"] == 1.0 and high["rk"] == 1.2
    assert high["total"] > low["total"]
    assert low["total"] == pytest.approx(50.0, abs=0.01)
    # 技术要求 0.6×70 = 42 + 管理要求 0.5×30 = 15 → 57
    assert high["total"] == pytest.approx(57.0, abs=0.01)


def test_evaluate_errors(client):
    assert client.post("/api/scoring/evaluate", json={"rows": []}).get_json()["code"] == 1
    bad_layer = [{"layer": "未知层面", "unit": "identity", "target": "x", "status": "full"}]
    body = client.post("/api/scoring/evaluate", json={"rows": bad_layer}).get_json()
    assert body["code"] == 1 and "层面" in body["msg"]
    bad_unit = [{"layer": "physical", "unit": "nope", "target": "x", "status": "full"}]
    assert client.post("/api/scoring/evaluate", json={"rows": bad_unit}).get_json()["code"] == 1
    bad_status = [{"layer": "physical", "unit": "identity", "target": "x", "status": "weird"}]
    assert client.post("/api/scoring/evaluate", json={"rows": bad_status}).get_json()["code"] == 1
    bad_ra = [{"layer": "physical", "unit": "identity", "target": "x", "status": "full"}]
    body = client.post("/api/scoring/evaluate", json={"rows": bad_ra, "ra": 0.9}).get_json()
    assert body["code"] == 1 and "Ra" in body["msg"]
    bad_comp = [{"layer": "physical", "unit": "identity", "target": "x", "status": "none",
                 "compensate": "不存在"}]
    body = client.post("/api/scoring/evaluate", json={"rows": bad_comp}).get_json()
    assert body["code"] == 1 and "弥补" in body["msg"]
    all_na = [{"layer": "physical", "unit": "identity", "target": "x", "status": "na"}]
    body = client.post("/api/scoring/evaluate", json={"rows": all_na}).get_json()
    assert body["code"] == 1


def test_rounding_4_and_2(client):
    rows = [
        {"layer": "physical", "unit": "identity", "target": "机房A", "status": "partial_both"},
        {"layer": "physical", "unit": "identity", "target": "机房B", "status": "partial_both"},
        {"layer": "physical", "unit": "identity", "target": "机房C", "status": "full"},
    ]
    data = ok_data(client, "/api/scoring/evaluate",
                   {"grade": 3, "rows": rows, "ra": 0.2, "moduleLevel": 0})
    # 0.25 × 0.2 × 1 = 0.05；均值 = (0.05+0.05+1)/3 = 0.3667
    unit = next(u for u in layer_of(data, "physical")["units"] if u["key"] == "identity")
    assert unit["score"] == pytest.approx(0.3667, abs=1e-4)
    assert len(str(data["total"]).split(".")[-1]) <= 2
