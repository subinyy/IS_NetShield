"""
3단계: 경쟁 모델과 성능 비교
우리 모델 vs Google Safe Browsing vs VirusTotal
"""

import os
import time
import json
import requests
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

# 2단계에서 저장한 모델과 예측 함수 재사용
import sys
sys.path.append(os.path.dirname(__file__))
from train_model import load_model, predict_url


# ─────────────────────────────────────────────────────────────
# 외부 API 래퍼
# ─────────────────────────────────────────────────────────────

def check_google_safe_browsing(url: str, api_key: str) -> int:
    """
    Google Safe Browsing API v4
    API 키 발급: https://developers.google.com/safe-browsing/v4/get-started
    반환: 1 (악성) / 0 (정상)
    """
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "url-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=5)
        data = resp.json()
        return 1 if data.get("matches") else 0
    except Exception:
        return -1  # 오류


def check_virustotal(url: str, api_key: str) -> dict:
    """
    VirusTotal URL 분석 API v3
    API 키 발급: https://www.virustotal.com/gui/join-us
    반환: {"score": 악성엔진수, "total": 전체엔진수, "label": 1/0}
    """
    import base64
    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            return {
                "score": malicious,
                "total": total,
                "label": 1 if malicious >= 3 else 0,  # 3개 이상 엔진 탐지 시 악성
            }
    except Exception:
        pass
    return {"score": -1, "total": 0, "label": -1}


# ─────────────────────────────────────────────────────────────
# 벤치마크 실행
# ─────────────────────────────────────────────────────────────

def run_benchmark(
    test_urls: list[dict],  # [{"url": ..., "true_label": 0 or 1}, ...]
    gsb_api_key: str = None,
    vt_api_key: str = None,
    model_path: str = "./model/xgb_model.pkl",
):
    """
    세 모델 동시 벤치마크 실행
    test_urls: 정답 레이블이 있는 URL 리스트
    """
    model, feature_names = load_model(model_path)

    results = []
    for item in test_urls:
        url = item["url"]
        true_label = item["true_label"]
        row = {"url": url, "true_label": true_label}

        # ── 우리 모델 ────────────────────────────────────────
        t0 = time.time()
        our_result = predict_url(url, model, feature_names)
        row["ours_pred"] = 1 if our_result["verdict"] == "block" else 0
        row["ours_score"] = our_result["score"]
        row["ours_latency_ms"] = round((time.time() - t0) * 1000, 2)

        # ── Google Safe Browsing ──────────────────────────────
        if gsb_api_key:
            t0 = time.time()
            row["gsb_pred"] = check_google_safe_browsing(url, gsb_api_key)
            row["gsb_latency_ms"] = round((time.time() - t0) * 1000, 2)
            time.sleep(0.1)  # API rate limit 방지

        # ── VirusTotal ────────────────────────────────────────
        if vt_api_key:
            t0 = time.time()
            vt = check_virustotal(url, vt_api_key)
            row["vt_pred"] = vt["label"]
            row["vt_engine_score"] = f"{vt['score']}/{vt['total']}"
            row["vt_latency_ms"] = round((time.time() - t0) * 1000, 2)
            time.sleep(0.2)  # VirusTotal rate limit (무료: 4req/min)

        results.append(row)
        print(f"  처리: {url[:60]}")

    return pd.DataFrame(results)


def print_comparison_report(df: pd.DataFrame):
    """비교 결과 표 출력"""
    y_true = df["true_label"]
    models = {}

    if "ours_pred" in df.columns:
        models["우리 모델 (XGBoost)"] = df["ours_pred"]
    if "gsb_pred" in df.columns and (df["gsb_pred"] != -1).all():
        models["Google Safe Browsing"] = df["gsb_pred"]
    if "vt_pred" in df.columns and (df["vt_pred"] != -1).all():
        models["VirusTotal (3+ engines)"] = df["vt_pred"]

    print("\n" + "=" * 65)
    print(f"{'모델':<25} {'Precision':>10} {'Recall':>8} {'F1':>8} {'응답시간':>10}")
    print("=" * 65)

    for name, preds in models.items():
        valid = preds != -1
        p = precision_score(y_true[valid], preds[valid], zero_division=0)
        r = recall_score(y_true[valid], preds[valid], zero_division=0)
        f1 = f1_score(y_true[valid], preds[valid], zero_division=0)

        latency_col = {"우리 모델 (XGBoost)": "ours_latency_ms",
                       "Google Safe Browsing": "gsb_latency_ms",
                       "VirusTotal (3+ engines)": "vt_latency_ms"}.get(name)
        avg_ms = f"{df[latency_col].mean():.1f}ms" if latency_col and latency_col in df else "N/A"

        print(f"{name:<25} {p:>10.4f} {r:>8.4f} {f1:>8.4f} {avg_ms:>10}")

    print("=" * 65)
    print("\n* Recall 우선: 악성 URL을 놓치는 것이 오탐보다 위험합니다.")

    df.to_csv("./results/benchmark_results.csv", index=False)
    print("상세 결과 저장: ./results/benchmark_results.csv")


# ─────────────────────────────────────────────────────────────
# 실행
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    GSB_KEY = "AIzaSyCYQZALt7ur_H7KRO7stFJihoRCaWQcZ7c"
    VT_KEY  = "d915ee3da2841f9cf59500282c198cb264f37f7b36f4b2eaa8833d80ac99dfda"

    # PhishTank 실제 피싱 URL 로드
    phish_df = pd.read_csv("online-valid.csv")
    phish_urls = phish_df["url"].dropna().head(10).tolist()

    test_set = []
    # 정상 URL (true_label=0)
    for url in [
        "https://www.google.com",
        "https://www.naver.com",
        "https://github.com",
        "https://www.youtube.com",
        "https://www.wikipedia.org",
    ]:
        test_set.append({"url": url, "true_label": 0})
    # 실제 피싱 URL (true_label=1)
    for url in phish_urls:
        test_set.append({"url": url, "true_label": 1})

    print(f"테스트셋: 정상 5개 + 실제 피싱 {len(phish_urls)}개")

    print("벤치마크 시작...")
    df = run_benchmark(test_set, gsb_api_key=GSB_KEY, vt_api_key=VT_KEY)
    print_comparison_report(df)