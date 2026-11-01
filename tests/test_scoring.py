"""量化评估（GB/T 39786-2021 四个技术层面）。

评分规则交叉验证：原站量化评估为纯前端计算（scoringView chunk 中
X / te / ne / oe 函数），本测试按原站同一套公式与分值复算层面得分率，
与本地实现逐层比对，验证「单元分值 = 对象均值」「层面得分率 = 加权平均」
「总分 = 各层面得分率 × 25%」三条规则一致。
"""
from __future__ import annotations

import copy

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


def full_objects(score: int) -> list:
    objects = []
    for layer in scoring.LAYERS:
        scores = {item["key"]: score for item in layer["items"]}
        objects.append({"layer": layer["key"], "name": layer["objectLabel"] + "1", "scores": scores})
    return objects


# ---------------------------------------------------------------------------
# 指标模型
# ---------------------------------------------------------------------------

def test_model_structure(client):
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    assert model["grade"] == 3 and model["gradeLabel"] == "三级"
    assert [layer["key"] for layer in model["layers"]] == ["physical", "network", "device", "app"]
    assert all(layer["weight"] == 0.25 for layer in model["layers"])
    counts = {layer["key"]: len(layer["items"]) for layer in model["layers"]}
    assert counts == {"physical": 3, "network": 5, "device": 6, "app": 8}
    assert model["thresholds"] == {"pass": 90.0, "basic": 70.0}
    names = {item["name"] for layer in model["layers"] for item in layer["items"]}
    for required in ("身份鉴别", "电子门禁记录数据存储完整性", "视频监控记录数据存储完整性",
                     "通信数据完整性", "安全接入认证", "日志记录完整性", "远程管理通道安全",
                     "重要可执行程序完整性、重要可执行程序来源真实性",
                     "重要数据传输机密性", "重要数据存储完整性", "不可否认性"):
        assert required in names


def test_model_grade2_is_subset(client):
    model2 = ok_data(client, "/api/scoring/model", {"grade": 2})
    counts = {layer["key"]: len(layer["items"]) for layer in model2["layers"]}
    assert counts == {"physical": 2, "network": 4, "device": 3, "app": 6}
    keys3 = {layer["key"]: {i["key"] for i in layer["items"]}
             for layer in ok_data(client, "/api/scoring/model", {"grade": 3})["layers"]}
    for layer in model2["layers"]:
        assert {i["key"] for i in layer["items"]} <= keys3[layer["key"]]


def test_model_get_and_bad_grade(client):
    assert client.get("/api/scoring/model?grade=4").get_json()["data"]["grade"] == 4
    body = client.post("/api/scoring/model", json={"grade": 5}).get_json()
    assert body["code"] == 1 and "等级" in body["msg"]


def test_default_objects(client):
    data = ok_data(client, "/api/scoring/default", {})
    assert len(data["objects"]) == 4
    assert {o["layer"] for o in data["objects"]} == {"physical", "network", "device", "app"}


# ---------------------------------------------------------------------------
# 评分计算
# ---------------------------------------------------------------------------

def test_evaluate_default_dataset(client):
    data = ok_data(client, "/api/scoring/evaluate",
                   {"grade": 3, "objects": copy.deepcopy(scoring.DEFAULT_OBJECTS)})
    assert data["total"] == pytest.approx(87.15, abs=0.01)
    assert data["grade"] == "基本符合"
    assert len(data["layers"]) == 4
    assert all(layer["weight"] == 0.25 for layer in data["layers"])
    # 层面得分都应按 0~100 归一
    for layer in data["layers"]:
        assert 0 <= layer["score"] <= 100
    # 明细条数 = 各层面「指标 × 对象」适用组合数
    expected = 0
    for layer in data["layers"]:
        for item in layer["items"]:
            if item["applicable"]:
                expected += len([o for o in item["objects"] if o["score"] is not None])
    assert len(data["details"]) == expected
    assert data["suggestions"], "存在非满分指标时应给出整改建议"


def test_evaluate_all_full_score(client):
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "objects": full_objects(3)})
    assert data["total"] == 100.0 and data["grade"] == "符合"
    assert data["suggestions"] == []
    for layer in data["layers"]:
        assert layer["score"] == 100.0


def test_evaluate_all_zero(client):
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "objects": full_objects(0)})
    assert data["total"] == 0.0 and data["grade"] == "不符合"
    assert "得分为 0" in data["gradeReason"]


def test_grade_thresholds(client):
    # 构造 90 分附近：三层满分、一层 60% → (100*3 + 60)/4 = 90
    objects = full_objects(3)
    for obj in objects:
        if obj["layer"] == "app":
            obj["scores"] = {k: (3 if i % 5 else 0) for i, k in enumerate(obj["scores"])}
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "objects": objects})
    assert data["total"] < 100
    # 一层 0 分直接判不符合
    zero_layer = full_objects(3)
    for obj in zero_layer:
        if obj["layer"] == "network":
            obj["scores"] = {k: 0 for k in obj["scores"]}
    bad = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "objects": zero_layer})
    assert bad["grade"] == "不符合" and "网络和通信安全" in bad["gradeReason"]


def test_multiple_objects_are_averaged(client):
    objects = [
        {"layer": "physical", "name": "机房A", "scores": {"identity": 3, "access_record": 3, "video_record": 3}},
        {"layer": "physical", "name": "机房B", "scores": {"identity": 0, "access_record": 0, "video_record": 0}},
        {"layer": "network", "name": "通道1", "scores": {i["key"]: 3 for i in scoring.LAYERS[1]["items"]}},
        {"layer": "device", "name": "设备1", "scores": {i["key"]: 3 for i in scoring.LAYERS[2]["items"]}},
        {"layer": "app", "name": "应用1", "scores": {i["key"]: 3 for i in scoring.LAYERS[3]["items"]}},
    ]
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "objects": objects})
    physical = next(layer for layer in data["layers"] if layer["key"] == "physical")
    assert physical["score"] == pytest.approx(50.0, abs=0.01)
    assert physical["objectCount"] == 2


def test_not_applicable_item_excluded(client):
    objects = copy.deepcopy(scoring.DEFAULT_OBJECTS)
    for obj in objects:
        if obj["layer"] == "device":
            obj["scores"]["executable"] = None   # 整项不适用（只有一个对象）
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "objects": objects})
    device = next(layer for layer in data["layers"] if layer["key"] == "device")
    item = next(i for i in device["items"] if i["key"] == "executable")
    assert item["applicable"] is False and item["unitScore"] is None
    assert device["applicableItems"] == 5
    assert data["stats"]["notApplicableItems"] == 1


def test_not_applicable_object_within_item(client):
    objects = copy.deepcopy(scoring.DEFAULT_OBJECTS)
    extra = {"layer": "physical", "name": "机房2",
             "scores": {"identity": None, "access_record": None, "video_record": None}}
    objects.append(extra)
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "objects": objects})
    physical = next(layer for layer in data["layers"] if layer["key"] == "physical")
    identity = next(i for i in physical["items"] if i["key"] == "identity")
    # 机房2 该项不适用，单元分值只按机房1 的 3 分计算
    assert identity["unitScore"] == 3.0


def test_evaluate_errors(client):
    assert client.post("/api/scoring/evaluate", json={"objects": []}).get_json()["code"] == 1
    bad_layer = [{"layer": "未知层面", "name": "x", "scores": {}}]
    body = client.post("/api/scoring/evaluate", json={"objects": bad_layer}).get_json()
    assert body["code"] == 1 and "层面" in body["msg"]
    bad_score = copy.deepcopy(scoring.DEFAULT_OBJECTS)
    bad_score[0]["scores"]["identity"] = 9
    body = client.post("/api/scoring/evaluate", json={"objects": bad_score}).get_json()
    assert body["code"] == 1 and "0~3" in body["msg"]
    no_name = copy.deepcopy(scoring.DEFAULT_OBJECTS)
    no_name[0]["name"] = " "
    assert client.post("/api/scoring/evaluate", json={"objects": no_name}).get_json()["code"] == 1
    too_few = copy.deepcopy(scoring.DEFAULT_OBJECTS)
    for obj in too_few:
        obj["scores"] = {k: None for k in obj["scores"]}
    body = client.post("/api/scoring/evaluate", json={"objects": too_few}).get_json()
    assert body["code"] == 1 and "不适用" in body["msg"]


def test_evaluate_grade2_ignores_grade3_items(client):
    objects = copy.deepcopy(scoring.DEFAULT_OBJECTS)
    data2 = ok_data(client, "/api/scoring/evaluate", {"grade": 2, "objects": objects})
    items = {(layer["key"], item["key"]) for layer in data2["layers"] for item in layer["items"]}
    assert ("physical", "video_record") not in items
    assert ("device", "remote_admin") not in items
    assert ("app", "non_repudiation") not in items
    assert len(items) == 15  # 2 + 4 + 3 + 6


# ---------------------------------------------------------------------------
# 与原站评分规则交叉复算
# ---------------------------------------------------------------------------

def original_layer_ratio(layer_key, objects, weights) -> float:
    """复刻原站 scoringView 中的 X（单元分值）与 ne/oe（层面加权平均）。

    原站对象分值范围为 0 / 0.25 / 0.5 / 1，本工具为 0~3 分，因此按 s/3 归一后
    公式完全一致：unitScore = mean(targetScore)，层面得分率 = Σ(unit×w)/Σw。
    """
    ratio_sum = 0.0
    weight_sum = 0.0
    for item_key, weight in weights.items():
        values = [o["scores"][item_key] / 3.0 for o in objects
                  if o["layer"] == layer_key and o["scores"].get(item_key) is not None]
        if not values:
            continue
        unit = sum(values) / len(values)
        ratio_sum += unit * weight
        weight_sum += weight
    return 0.0 if weight_sum == 0 else ratio_sum / weight_sum


def test_layer_scores_match_original_formula(client):
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    weights = {layer["key"]: {item["key"]: item["weight"] for item in layer["items"]}
               for layer in model["layers"]}
    objects = copy.deepcopy(scoring.DEFAULT_OBJECTS)
    data = ok_data(client, "/api/scoring/evaluate", {"grade": 3, "objects": objects})
    for layer in data["layers"]:
        expected = original_layer_ratio(layer["key"], objects, weights[layer["key"]])
        assert layer["ratio"] == pytest.approx(round(expected, 4), abs=1e-4)
        assert layer["score"] == pytest.approx(round(expected * 100, 2), abs=0.01)
    # 总分 = Σ(层面得分率 × 25%)
    total = sum(layer["ratio"] * 0.25 for layer in data["layers"]) * 100
    assert data["total"] == pytest.approx(round(total, 2), abs=0.01)


def test_weights_cover_all_items(client):
    model = ok_data(client, "/api/scoring/model", {"grade": 3})
    for layer in model["layers"]:
        assert all(item["weight"] in (1.0, 0.7) for item in layer["items"])
        assert layer["weight"] * 4 == 1.0
