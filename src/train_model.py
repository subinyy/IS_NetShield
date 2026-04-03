"""
2단계: 모델 학습 및 평가
XGBoost 모델을 학습하고 성능을 측정합니다.

필요한 패키지:
    pip install xgboost scikit-learn pandas numpy matplotlib seaborn
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, f1_score, precision_score, recall_score
)
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
import sys
import os
plt.rcParams['font.family'] = 'Malgun Gothic'

sys.path.append(os.path.dirname(__file__))
from feature_engineering import extract_features


# ─────────────────────────────────────────────────────────────
# 1. 데이터 로드
# ─────────────────────────────────────────────────────────────

def load_dataset(csv_path: str) -> pd.DataFrame:
    """
    Kaggle Malicious URL Dataset 로드
    컬럼: url, type (benign / phishing / malware / defacement)

    다운로드: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
    """
    df = pd.read_csv(csv_path)
    print(f"총 데이터: {len(df):,}개")
    print(df["type"].value_counts())
    return df


def load_sample_data() -> pd.DataFrame:
    """
    실제 데이터셋 없을 때 사용하는 샘플 데이터
    모델 코드 검증용 (실제 성능 평가에는 사용 금지)
    """
    sample = [
        ("https://www.google.com", "benign"),
        ("https://www.naver.com", "benign"),
        ("https://github.com/user/repo", "benign"),
        ("https://www.amazon.com/product/123", "benign"),
        ("https://stackoverflow.com/questions/1234", "benign"),
        ("http://paypa1-secure.xyz/login/verify", "phishing"),
        ("http://free-gift-amazon.tk/claim", "phishing"),
        ("http://192.168.1.1/admin", "phishing"),
        ("https://g00gle.com/accounts/signin", "phishing"),
        ("http://secure-banklogin.ml/auth", "phishing"),
        ("http://malware-host.ru/download/virus.exe", "malware"),
        ("http://evil.tk/payload.php?cmd=exec", "malware"),
    ]
    df = pd.DataFrame(sample, columns=["url", "type"])
    print(f"샘플 데이터 {len(df)}개 로드됨 (실제 데이터셋으로 교체 필요)")
    return df


# ─────────────────────────────────────────────────────────────
# 2. 피처 추출
# ─────────────────────────────────────────────────────────────

def build_feature_matrix(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """URL 목록에서 피처 행렬 생성"""
    print("피처 추출 중...")
    features_list = []

    for i, url in enumerate(df["url"]):
        if i % 10000 == 0 and i > 0:
            print(f"  {i:,} / {len(df):,} 처리 완료")
        try:
            features_list.append(extract_features(str(url)))
        except Exception:
            features_list.append({})

    X = pd.DataFrame(features_list).fillna(0)

    # 레이블 이진화 (benign=0, 나머지=1)
    y = (df["type"] != "benign").astype(int)

    print(f"\n피처 개수: {X.shape[1]}")
    print(f"정상 URL: {(y == 0).sum():,} | 악성 URL: {(y == 1).sum():,}")
    return X, y


# ─────────────────────────────────────────────────────────────
# 3. 모델 학습
# ─────────────────────────────────────────────────────────────

def train_model(X: pd.DataFrame, y: pd.Series) -> tuple:
    """XGBoost 학습 + 평가"""

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=(y == 0).sum() / (y == 1).sum(),  # 클래스 불균형 보정
        random_state=42,
        eval_metric="logloss",
        early_stopping_rounds=20,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    return model, X_train, X_test, y_train, y_test


# ─────────────────────────────────────────────────────────────
# 4. 성능 평가
# ─────────────────────────────────────────────────────────────

def evaluate_model(model, X_test, y_test, save_dir="./results"):
    """성능 지표 출력 + 시각화 저장"""
    os.makedirs(save_dir, exist_ok=True)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    # ── 핵심 지표 ────────────────────────────────────────────
    metrics = {
        "Accuracy":  round((y_pred == y_test).mean(), 4),
        "Precision": round(float(precision_score(y_test, y_pred)), 4),
        "Recall":    round(float(recall_score(y_test, y_pred)), 4),
        "F1 Score":  round(float(f1_score(y_test, y_pred)), 4),
        "ROC-AUC":   round(float(roc_auc_score(y_test, y_prob)), 4),
        "FP Rate":   round((((y_pred == 1) & (y_test == 0)).sum() / (y_test == 0).sum()), 4),
    }

    print("\n" + "=" * 50)
    print("모델 성능 결과")
    print("=" * 50)
    for k, v in metrics.items():
        print(f"  {k:<12}: {v:.4f}")
    print("=" * 50)
    print("\n분류 리포트:\n")
    print(classification_report(y_test, y_pred, target_names=["정상", "악성"]))

    # ── Confusion Matrix 시각화 ───────────────────────────────
    cm = confusion_matrix(y_test, y_pred)
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=axes[0],
                xticklabels=["정상", "악성"],
                yticklabels=["정상", "악성"])
    axes[0].set_title("Confusion Matrix")
    axes[0].set_xlabel("예측")
    axes[0].set_ylabel("실제")

    # ── 피처 중요도 ───────────────────────────────────────────
    importances = pd.Series(
        model.feature_importances_,
        index=model.get_booster().feature_names
    ).sort_values(ascending=True).tail(15)

    importances.plot(kind="barh", ax=axes[1], color="#378ADD")
    axes[1].set_title("Feature Importance (Top 15)")
    axes[1].set_xlabel("Importance Score")

    plt.tight_layout()
    fig.savefig(f"{save_dir}/model_evaluation.png", dpi=150, bbox_inches="tight")
    print(f"\n시각화 저장: {save_dir}/model_evaluation.png")

    return metrics


# ─────────────────────────────────────────────────────────────
# 5. 모델 저장
# ─────────────────────────────────────────────────────────────

def save_model(model, feature_names: list, path="./model"):
    """모델 + 피처 목록 저장 (FastAPI 서빙용)"""
    os.makedirs(path, exist_ok=True)
    with open(f"{path}/xgb_model.pkl", "wb") as f:
        pickle.dump({"model": model, "feature_names": feature_names}, f)
    print(f"모델 저장: {path}/xgb_model.pkl")


def load_model(path="./model/xgb_model.pkl"):
    with open(path, "rb") as f:
        data = pickle.load(f)
    return data["model"], data["feature_names"]


# ─────────────────────────────────────────────────────────────
# 6. 단일 URL 예측 (API 연동용)
# ─────────────────────────────────────────────────────────────

def predict_url(url: str, model, feature_names: list) -> dict:
    """
    URL 하나를 받아 위험도 점수와 판정을 반환
    FastAPI 엔드포인트에서 이 함수를 호출합니다.
    """
    features = extract_features(url)
    X = pd.DataFrame([features])[feature_names].fillna(0)
    prob = model.predict_proba(X)[0][1]
    score = int(prob * 100)

    if score >= 70:
        verdict = "block"
        label = "위험"
    elif score >= 40:
        verdict = "alert"
        label = "경고"
    else:
        verdict = "allow"
        label = "정상"

    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "label": label,
        "top_features": _get_triggered_features(features),
    }


def _get_triggered_features(features: dict) -> list[str]:
    """위험 판단에 기여한 주요 피처 반환 (UI 표시용)"""
    reasons = []
    if features.get("has_ip_address"):       reasons.append("IP 주소 직접 사용")
    if features.get("has_phishing_keyword"): reasons.append("피싱 키워드 포함")
    if features.get("has_brand_keyword"):    reasons.append("브랜드 사칭 의심")
    if features.get("has_typosquatting"):    reasons.append("타이포스쿼팅 탐지")
    if features.get("tld_risk", 0) >= 2:     reasons.append("고위험 TLD 도메인")
    if features.get("count_at", 0) > 0:      reasons.append("@ 문자 포함")
    if not features.get("is_https"):         reasons.append("HTTP 비암호화")
    if features.get("url_entropy", 0) > 4.5: reasons.append("URL 난독화 의심")
    return reasons


# ─────────────────────────────────────────────────────────────
# 실행
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    df = load_dataset("F:\\other_class\\Information_Security\\malicious_phish.csv")
    #df = load_sample_data()

    X, y = build_feature_matrix(df)
    model, X_train, X_test, y_train, y_test = train_model(X, y)
    metrics = evaluate_model(model, X_test, y_test)
    save_model(model, list(X.columns))

    print("\n── 예측 테스트 ──────────────────────────────────────")
    test_urls = [
        "https://www.google.com",
        "http://paypa1-secure.xyz/login/verify",
        "http://free-gift-amazon.tk/claim",
    ]
    m, feat_names = load_model()
    for url in test_urls:
        result = predict_url(url, m, feat_names)
        print(f"\n{result['url']}")
        print(f"  점수: {result['score']}/100  판정: {result['label']}")
        if result["top_features"]:
            print(f"  이유: {', '.join(result['top_features'])}")
