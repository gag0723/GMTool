"""量化评估接口（GB/T 39786-2021 四个技术层面）。

路由：

* ``POST /api/scoring/model``     返回指标模型（按系统等级裁剪），供前端渲染可编辑表格
* ``GET  /api/scoring/model``     同上（query 参数 ``grade``）
* ``POST /api/scoring/evaluate``  提交测评对象分值，返回总分、等级、层面得分卡、明细与整改建议
* ``POST /api/scoring/default``   返回默认测评对象（示例机房/通道/设备/应用）
"""
from __future__ import annotations

import copy

from flask import Blueprint, request

from ..core import scoring
from ..core.common import ok

bp = Blueprint("scoring", __name__, url_prefix="/api/scoring")


def _p() -> dict:
    return request.get_json(silent=True) or {}


def _grade_from(value):
    return 3 if value in (None, "") else value


@bp.post("/model")
def model_post():
    return ok(scoring.model(_grade_from(_p().get("grade"))))


@bp.get("/model")
def model_get():
    return ok(scoring.model(_grade_from(request.args.get("grade"))))


@bp.post("/evaluate")
def evaluate():
    p = _p()
    payload = dict(p)
    if "objects" not in payload and isinstance(p.get("data"), dict):
        payload.update(p["data"])
    return ok(scoring.evaluate(payload))


@bp.post("/default")
def default_objects():
    grade = _grade_from(_p().get("grade"))
    return ok({"grade": grade, "objects": copy.deepcopy(scoring.DEFAULT_OBJECTS)})
