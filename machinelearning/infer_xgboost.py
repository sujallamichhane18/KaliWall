#!/usr/bin/env python3
"""Bridge script: run XGBoost joblib anomaly inference from stdin JSON.

Input JSON shape:
{
  "model_path": "machinelearning/xgboost_anomaly_model.joblib",
  "metadata_path": "machinelearning/training_metadata.json",
  "features": {"f1": 1.2, "f2": 0.3},
    "threshold": 0.55,
    "force_cpu": true
}

Output JSON shape:
{
  "ok": true,
  "score": 0.87,
  "threshold": 0.55,
  "is_anomaly": true,
  "predicted_class": 1,
  "feature_count": 78,
  "warning": "...optional..."
}
"""

from __future__ import annotations

import json
import math
import os
import sys
from dataclasses import dataclass
from typing import Any

import joblib
import numpy as np

try:
    import xgboost as xgb
except Exception:
    xgb = None


@dataclass
class Metadata:
    feature_names: list[str]
    threshold: float | None


def _debug(message: str) -> None:
    print(f"[infer_xgboost] {message}", file=sys.stderr, flush=True)


def _model_type_name(model: Any) -> str:
    if model is None:
        return "None"
    return f"{type(model).__module__}.{type(model).__name__}"


def _emit(payload: dict[str, Any], code: int = 0) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")))
    sys.stdout.flush()
    raise SystemExit(code)


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _to_bool(v: Any, default: bool) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        raw = v.strip().lower()
        if raw in {"1", "true", "yes", "y", "on"}:
            return True
        if raw in {"0", "false", "no", "n", "off"}:
            return False
    return default


def _extract_feature_names(meta_obj: Any) -> list[str]:
    if not isinstance(meta_obj, dict):
        return []

    candidates = []
    for key in ("feature_names", "features", "columns", "model_features"):
        val = meta_obj.get(key)
        if isinstance(val, list):
            filtered = [str(item).strip() for item in val if str(item).strip()]
            if filtered:
                candidates.append(filtered)

    if candidates:
        return candidates[0]
    return []


def _extract_threshold(meta_obj: Any) -> float | None:
    if not isinstance(meta_obj, dict):
        return None

    for key in (
        "threshold",
        "best_threshold",
        "decision_threshold",
        "anomaly_threshold",
        "optimal_threshold",
    ):
        if key in meta_obj:
            try:
                return _clamp01(float(meta_obj[key]))
            except Exception:
                return None
    return None


def _load_metadata(path: str | None) -> Metadata:
    if not path:
        return Metadata(feature_names=[], threshold=None)

    if not os.path.isfile(path):
        return Metadata(feature_names=[], threshold=None)

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return Metadata(
            feature_names=_extract_feature_names(raw),
            threshold=_extract_threshold(raw),
        )
    except Exception:
        return Metadata(feature_names=[], threshold=None)


def _feature_names_from_model(model: Any) -> list[str]:
    # sklearn-compatible models
    if hasattr(model, "feature_names_in_"):
        names = getattr(model, "feature_names_in_", None)
        if names is not None:
            out = [str(v).strip() for v in names if str(v).strip()]
            if out:
                return out

    # xgboost sklearn wrapper exposes booster feature names
    if hasattr(model, "get_booster"):
        try:
            booster = model.get_booster()
            names = getattr(booster, "feature_names", None)
            if names:
                out = [str(v).strip() for v in names if str(v).strip()]
                if out:
                    return out
        except Exception:
            pass

    # raw booster object may expose feature names directly
    names = getattr(model, "feature_names", None)
    if names:
        out = [str(v).strip() for v in names if str(v).strip()]
        if out:
            return out

    return []


def _load_model(model_path: str) -> tuple[Any, str]:
    """Load model from JSON/UBJ via Booster or from joblib for sklearn-style wrappers.

    Returns:
        (model_object, load_mode)
    """

    ext = os.path.splitext(model_path)[1].lower()
    booster_exts = {".json", ".ubj"}

    if ext in booster_exts:
        if xgb is None:
            raise RuntimeError(
                f"xgboost is required to load {ext} model files via Booster.load_model"
            )
        booster = xgb.Booster()
        booster.load_model(model_path)
        return booster, "booster"

    try:
        model = joblib.load(model_path)
        return model, "joblib"
    except Exception as exc:
        _debug(
            "joblib.load failed "
            f"(path={model_path}, ext={ext or 'none'}, expected=joblib/sklearn-wrapper): {exc}"
        )

    if xgb is not None:
        try:
            booster = xgb.Booster()
            booster.load_model(model_path)
            return booster, "booster"
        except Exception as booster_exc:
            _debug(
                "Booster.load_model fallback failed "
                f"(path={model_path}, ext={ext or 'none'}, expected=xgboost.Booster): {booster_exc}"
            )
            raise RuntimeError(
                "failed to load model using both joblib and xgboost.Booster loaders"
            ) from booster_exc

    raise RuntimeError(
        "failed loading model with joblib and xgboost is unavailable for Booster fallback"
    )


def _force_cpu_inference(model: Any) -> str:
    """Best-effort CPU pinning for XGBoost models.

    This is intentionally defensive: each parameter set is attempted independently,
    and unsupported parameters are ignored so inference can proceed.
    """

    # sklearn-style wrapper path
    if hasattr(model, "set_params"):
        for params in (
            {"device": "cpu"},
            {"tree_method": "hist"},
            {"predictor": "cpu_predictor"},
        ):
            try:
                model.set_params(**params)
            except Exception:
                pass

    # Booster-level path
    if hasattr(model, "get_booster"):
        try:
            booster = model.get_booster()
            for params in (
                {"device": "cpu"},
                {"tree_method": "hist"},
                {"predictor": "cpu_predictor"},
            ):
                try:
                    booster.set_param(params)
                except Exception:
                    pass
        except Exception as exc:
            return f"failed to force CPU mode on booster: {exc}"

    # Raw Booster path
    if xgb is not None and isinstance(model, xgb.Booster):
        for params in (
            {"device": "cpu"},
            {"tree_method": "hist"},
            {"predictor": "cpu_predictor"},
        ):
            try:
                model.set_param(params)
            except Exception:
                pass

    return ""


def _predict_score(model: Any, matrix: np.ndarray, feature_names: list[str]) -> float:
    # 1) Classifier-style probability prediction when available
    if hasattr(model, "predict_proba"):
        try:
            probs = model.predict_proba(matrix)
            arr = np.asarray(probs)
            if arr.ndim == 2 and arr.shape[1] >= 2:
                return _clamp01(float(arr[0, 1]))
            if arr.ndim >= 1:
                return _clamp01(float(arr.reshape(-1)[0]))
        except Exception as exc:
            _debug(f"predict_proba failed for model type={_model_type_name(model)}: {exc}")

    # 2) Raw XGBoost Booster prediction path
    if xgb is not None and isinstance(model, xgb.Booster):
        dmatrix = xgb.DMatrix(
            matrix,
            feature_names=feature_names if feature_names else None,
        )
        raw = model.predict(dmatrix)
        arr = np.asarray(raw)
        if arr.ndim == 2 and arr.shape[1] >= 2:
            value = float(arr[0, 1])
        else:
            value = float(arr.reshape(-1)[0])
        if 0.0 <= value <= 1.0:
            return _clamp01(value)
        return _clamp01(_sigmoid(value))

    # 3) Decision-function fallback (common in sklearn estimators)
    if hasattr(model, "decision_function"):
        try:
            decision = model.decision_function(matrix)
            score = float(np.asarray(decision).reshape(-1)[0])
            return _clamp01(_sigmoid(score))
        except Exception as exc:
            _debug(f"decision_function failed for model type={_model_type_name(model)}: {exc}")

    # 4) Generic predict fallback for regressors/classifiers
    if hasattr(model, "predict"):
        pred = model.predict(matrix)
        arr = np.asarray(pred)
        if arr.ndim == 2 and arr.shape[1] >= 2:
            value = float(arr[0, 1])
        else:
            value = float(arr.reshape(-1)[0])
        if 0.0 <= value <= 1.0:
            return _clamp01(value)
        return _clamp01(_sigmoid(value))

    raise RuntimeError(
        f"model does not expose supported prediction methods (type={_model_type_name(model)})"
    )


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception as exc:
        _emit({"ok": False, "error": f"invalid input JSON: {exc}"}, code=2)

    model_path = str(payload.get("model_path", "")).strip()
    metadata_path = str(payload.get("metadata_path", "")).strip()
    features_obj = payload.get("features")
    req_threshold = payload.get("threshold", None)
    req_force_cpu = payload.get("force_cpu", None)

    if not model_path:
        _emit({"ok": False, "error": "model_path is required"}, code=2)
    if not os.path.isfile(model_path):
        _emit({"ok": False, "error": f"model not found: {model_path}"}, code=2)
    if not isinstance(features_obj, dict):
        _emit({"ok": False, "error": "features must be a JSON object"}, code=2)

    metadata = _load_metadata(metadata_path if metadata_path else None)

    try:
        model, load_mode = _load_model(model_path)
    except Exception as exc:
        _debug(
            "model load failed "
            f"(path={model_path}, ext={os.path.splitext(model_path)[1].lower() or 'none'}): {exc}"
        )
        _emit({"ok": False, "error": f"failed loading model: {exc}"}, code=2)

    _debug(f"loaded model type={_model_type_name(model)} mode={load_mode}")

    env_force_cpu = _to_bool(os.getenv("KALIWALL_ML_FORCE_CPU", "1"), True)
    force_cpu = _to_bool(req_force_cpu, env_force_cpu)

    warning = ""
    if force_cpu:
        cpu_warning = _force_cpu_inference(model)
        if cpu_warning:
            warning = cpu_warning

    feature_names = list(metadata.feature_names)

    if not feature_names:
        feature_names = _feature_names_from_model(model)
    if not feature_names:
        # Last-resort deterministic ordering.
        feature_names = sorted(str(k).strip() for k in features_obj.keys() if str(k).strip())
        feature_warning = (
            "Feature names were not found in metadata/model. "
            "Using sorted request feature names; verify training feature order."
        )
        warning = (warning + " " + feature_warning).strip()

    vector = np.array([
        _to_float(features_obj.get(name, 0.0), 0.0) for name in feature_names
    ], dtype=np.float32).reshape(1, -1)

    try:
        score = _predict_score(model, vector, feature_names)
    except Exception as exc:
        _debug(f"prediction failed for model type={_model_type_name(model)}: {exc}")
        _emit({"ok": False, "error": f"prediction failed: {exc}"}, code=2)

    threshold = metadata.threshold if metadata.threshold is not None else 0.5
    if req_threshold is not None:
        threshold = _clamp01(_to_float(req_threshold, threshold))

    is_anomaly = bool(score >= threshold)
    predicted_class = 1 if is_anomaly else 0

    _emit(
        {
            "ok": True,
            "score": float(score),
            "threshold": float(threshold),
            "is_anomaly": is_anomaly,
            "predicted_class": predicted_class,
            "feature_count": len(feature_names),
            "warning": warning,
            "inference_device": "cpu" if force_cpu else "auto",
        }
    )


if __name__ == "__main__":
    main()
