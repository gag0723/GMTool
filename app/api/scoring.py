"""量化评估接口（《商用密码应用安全性评估量化评估规则》2023 版）。

路由：

* ``POST /api/scoring/model``     返回指标模型（按密码应用级别 1~4 裁剪）
* ``GET  /api/scoring/model``     同上（query 参数 ``grade``）
* ``POST /api/scoring/default``   返回该等级的默认测评对象与判定（示例数据）
* ``GET  /api/scoring/default``   同上（query 参数 ``grade``）
* ``POST /api/scoring/evaluate``  提交测评对象判定，返回总分、结论、层面得分、明细、弥补与整改建议
"""
from __future__ import annotations

from flask import Blueprint, request

from ..core import scoring
from ..core.common import ok

bp = Blueprint("scoring", __name__, url_prefix="/api/scoring")


def _p() -> dict:
    return request.get_json(silent=True) or {}


@bp.post("/model")
def model_post():
    return ok(scoring.model(_p().get("grade")))


@bp.get("/model")
def model_get():
    return ok(scoring.model(request.args.get("grade")))


@bp.post("/default")
def default_post():
    grade = scoring.grade_of(_p().get("grade"))
    return ok({"grade": grade, "gradeLabel": scoring.GRADES[grade], "rows": scoring.default_rows(grade)})


@bp.get("/default")
def default_get():
    grade = scoring.grade_of(request.args.get("grade"))
    return ok({"grade": grade, "gradeLabel": scoring.GRADES[grade], "rows": scoring.default_rows(grade)})


@bp.post("/evaluate")
def evaluate():
    p = _p()
    payload = dict(p)
    if "rows" not in payload and isinstance(p.get("data"), dict):
        payload.update(p["data"])
    return ok(scoring.evaluate(payload))
