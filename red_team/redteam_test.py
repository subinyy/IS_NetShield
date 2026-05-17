"""
IS_NetShield 레드팀 검증 스크립트
1. 실제 데이터셋으로 모델 성능 검증
2. URL 우회 패턴 (Evasion Attack) 테스트
3. 결과 시각화
"""

import requests
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import time
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score
)

# ── 설정 ──────────────────────────────────────────────────
API_URL   = "http://13.209.5.230:8000/predict"
CSV_PATH  = "final_dataset_with_all_features_v3.1.csv"
SAMPLE_N  = 200   # 테스트할 URL 수 (너무 많으면 시간 오래 걸림)
SLEEP_SEC = 0.05  # API 과부하 방지
import matplotlib
import platform
if platform.system() == "Windows":
    plt.rcParams["font.family"] = "Malgun Gothic"
elif platform.system() == "Darwin":
    plt.rcParams["font.family"] = "AppleGothic"
else:
    plt.rcParams["font.family"] = "DejaVu Sans"
plt.rcParams["axes.unicode_minus"] = False

# ─────────────────────────────────────────────────────────
# 1. API 호출 함수
# ─────────────────────────────────────────────────────────

def call_api(url: str) -> dict:
    try:
        r = requests.post(
            API_URL,
            json={"url": url},
            timeout=8
        )
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"  오류: {e}")
    return None


def get_verdict(result: dict) -> int:
    """API 결과 → 이진 레이블 (0=정상, 1=악성)"""
    if result is None:
        return -1
    return 1 if result.get("is_malicious") else 0


# ─────────────────────────────────────────────────────────
# 2. 데이터셋 기반 검증
# ─────────────────────────────────────────────────────────

def run_dataset_validation():
    print("\n" + "="*60)
    print("[ 1단계 ] 실제 데이터셋 기반 모델 검증")
    print("="*60)

    df = pd.read_csv(CSV_PATH, usecols=["url", "type", "label"])
    df["is_malicious_gt"] = (df["label"] != 0).astype(int)

    # 클래스별 균등 샘플링
    n_each = SAMPLE_N // 4
    sampled = pd.concat([
        df[df["type"] == t].sample(min(n_each, len(df[df["type"] == t])), random_state=42)
        for t in ["benign", "phishing", "malware", "defacement"]
    ]).reset_index(drop=True)

    print(f"테스트 URL 수: {len(sampled)}개")
    print(sampled["type"].value_counts().to_string())

    results = []
    for i, row in sampled.iterrows():
        result = call_api(str(row["url"]))
        pred = get_verdict(result)
        prob = result.get("probability", 0) if result else 0
        risk = result.get("risk_level", "ERROR") if result else "ERROR"

        results.append({
            "url":      row["url"],
            "type":     row["type"],
            "gt":       row["is_malicious_gt"],
            "pred":     pred,
            "prob":     prob,
            "risk":     risk,
        })

        status = "✅" if pred == row["is_malicious_gt"] else "❌"
        print(f"  [{i+1:03d}] {status} {row['type']:<12} | {str(row['url'])[:50]}")
        time.sleep(SLEEP_SEC)

    df_res = pd.DataFrame(results)
    df_res = df_res[df_res["pred"] != -1]  # API 오류 제거

    y_true = df_res["gt"]
    y_pred = df_res["pred"]

    print("\n" + "─"*60)
    print("모델 성능 결과")
    print("─"*60)
    print(classification_report(y_true, y_pred, target_names=["정상", "악성"]))

    metrics = {
        "Accuracy":  round((y_true == y_pred).mean(), 4),
        "Precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "Recall":    round(recall_score(y_true, y_pred, zero_division=0), 4),
        "F1 Score":  round(f1_score(y_true, y_pred, zero_division=0), 4),
    }
    for k, v in metrics.items():
        print(f"  {k:<12}: {v:.4f}")

    return df_res, metrics


# ─────────────────────────────────────────────────────────
# 3. 우회 패턴 테스트 (Evasion Attack)
# ─────────────────────────────────────────────────────────

EVASION_URLS = [
    # 서브도메인 트릭
    ("서브도메인 트릭",       "https://paypal.com.evil-login.xyz/secure"),
    ("서브도메인 트릭",       "https://accounts.google.com.phish.top/signin"),
    ("서브도메인 트릭",       "https://apple.com.id-verify.net/account"),

    # @ 트릭
    ("@ 트릭",               "https://paypal.com@evil.com/login"),
    ("@ 트릭",               "http://google.com@192.168.1.1/auth"),

    # 정상 도메인 URL에 삽입
    ("정상 도메인 삽입",      "http://evil.com/https://paypal.com/login"),
    ("정상 도메인 삽입",      "http://malware.tk/?redirect=https://google.com"),

    # 단축 URL (실제 악성 숨기기)
    ("단축 URL",              "https://bit.ly/3xFreeGift"),
    ("단축 URL",              "https://tinyurl.com/secure-bank-login"),

    # 인코딩 우회
    ("URL 인코딩",            "http://payp%61l-login.com/verify"),
    ("URL 인코딩",            "http://g%6Fogle-secure.xyz/account"),

    # 하이픈 분산
    ("하이픈 분산",           "http://pay-pal-secure-login-verify.com"),
    ("하이픈 분산",           "http://face-book-account-update.net/login"),

    # 숫자 치환 (leetspeak)
    ("숫자 치환",             "http://payp4l-secur3.com/l0gin"),
    ("숫자 치환",             "http://g00gle-acc0unt.xyz/signin"),

    # 정상처럼 보이는 URL
    ("정상 위장",             "https://secure-paypal-helpdesk.com"),
    ("정상 위장",             "https://apple-id-support-center.com/verify"),
    ("정상 위장",             "https://amazon-customer-service.com/account"),

    # IP 직접 접속
    ("IP 직접 접속",          "http://192.168.1.1/admin/login.php"),
    ("IP 직접 접속",          "http://10.0.0.1/phishing/page"),
]


def run_evasion_test():
    print("\n" + "="*60)
    print("[ 2단계 ] 우회 패턴 (Evasion Attack) 테스트")
    print("="*60)

    results = []
    for pattern, url in EVASION_URLS:
        result = call_api(url)
        if result:
            detected = result.get("is_malicious", False)
            prob     = result.get("probability", 0)
            risk     = result.get("risk_level", "?")
            status   = "🚫 탐지됨" if detected else "⚠️  우회 성공"
            print(f"  {status} | {pattern:<14} | {prob:.3f} | {url[:55]}")
            results.append({
                "pattern": pattern,
                "url":     url,
                "detected":detected,
                "prob":    prob,
                "risk":    risk,
            })
        else:
            print(f"  ❌ API 오류  | {pattern:<14} | {url[:55]}")
        time.sleep(SLEEP_SEC)

    df_ev = pd.DataFrame(results)
    detected_rate = df_ev["detected"].mean() * 100
    print(f"\n우회 시도 {len(df_ev)}개 중 탐지: {df_ev['detected'].sum()}개 ({detected_rate:.1f}%)")
    print(f"우회 성공: {(~df_ev['detected']).sum()}개 ({100 - detected_rate:.1f}%)")

    return df_ev


# ─────────────────────────────────────────────────────────
# 4. 시각화
# ─────────────────────────────────────────────────────────

def draw_graphs(df_res, metrics, df_ev):
    fig, axes = plt.subplots(2, 3, figsize=(18, 11))
    fig.suptitle("NetShield Red Team Validation Report", fontsize=16, fontweight="bold", y=0.98)

    colors = {"benign": "#639922", "phishing": "#E24B4A", "malware": "#C04828", "defacement": "#EF9F27"}

    # ── 그래프 1: 클래스별 탐지율 ──────────────────────────
    ax = axes[0][0]
    type_stats = []
    for t in ["benign", "phishing", "malware", "defacement"]:
        sub = df_res[df_res["type"] == t]
        if len(sub) == 0: continue
        if t == "benign":
            correct = (sub["pred"] == 0).sum()
        else:
            correct = (sub["pred"] == 1).sum()
        rate = correct / len(sub) * 100
        type_stats.append({"type": t, "rate": rate, "n": len(sub)})

    df_ts = pd.DataFrame(type_stats)
    bars = ax.bar(df_ts["type"], df_ts["rate"],
                  color=[colors[t] for t in df_ts["type"]], alpha=0.85, edgecolor="white")
    for bar, row in zip(bars, df_ts.itertuples()):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{row.rate:.1f}%\n(n={row.n})", ha="center", va="bottom", fontsize=9)
    ax.set_title("클래스별 탐지율", fontweight="bold")
    ax.set_ylabel("Correct Detection Rate (%)")
    ax.set_ylim(0, 115)
    ax.axhline(y=90, color="gray", linestyle="--", alpha=0.5, label="90% 기준선")
    ax.legend(fontsize=8)

    # ── 그래프 2: Confusion Matrix ─────────────────────────
    ax = axes[0][1]
    cm = confusion_matrix(df_res["gt"], df_res["pred"])
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    fig.colorbar(im, ax=ax, fraction=0.046)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                    color="white" if cm[i, j] > cm.max()/2 else "black", fontsize=12)
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Predicted\nBenign", "Predicted\nMalicious"])
    ax.set_yticklabels(["Actual\nBenign", "Actual\nMalicious"])
    ax.set_title("Confusion Matrix", fontweight="bold")

    # ── 그래프 3: 성능 지표 바 ────────────────────────────
    ax = axes[0][2]
    metric_colors = ["#185FA5", "#E24B4A", "#639922", "#EF9F27"]
    bars = ax.bar(list(metrics.keys()), list(metrics.values()),
                  color=metric_colors, alpha=0.85, edgecolor="white")
    for bar, val in zip(bars, metrics.values()):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f"{val:.4f}", ha="center", va="bottom", fontsize=10, fontweight="bold")
    ax.set_title("모델 성능 지표", fontweight="bold")
    ax.set_ylim(0, 1.15)
    ax.axhline(y=0.9, color="gray", linestyle="--", alpha=0.5)

    # ── 그래프 4: 확률 분포 (정상 vs 악성) ────────────────
    ax = axes[1][0]
    benign_probs   = df_res[df_res["gt"] == 0]["prob"]
    malicious_probs = df_res[df_res["gt"] == 1]["prob"]
    ax.hist(benign_probs,   bins=20, alpha=0.6, color="#639922", label="정상 URL", edgecolor="white")
    ax.hist(malicious_probs, bins=20, alpha=0.6, color="#E24B4A", label="악성 URL", edgecolor="white")
    ax.axvline(x=0.5, color="black", linestyle="--", label="임계값 0.5")
    ax.set_title("악성 확률 분포", fontweight="bold")
    ax.set_xlabel("Malicious Probability")
    ax.set_ylabel("Count")
    ax.legend()

    # ── 그래프 5: 우회 패턴별 탐지율 ─────────────────────
    ax = axes[1][1]
    pattern_stats = df_ev.groupby("pattern")["detected"].agg(["sum", "count"]).reset_index()
    pattern_stats["rate"] = pattern_stats["sum"] / pattern_stats["count"] * 100
    bar_colors = ["#639922" if r >= 80 else "#EF9F27" if r >= 50 else "#E24B4A"
                  for r in pattern_stats["rate"]]
    bars = ax.barh(pattern_stats["pattern"], pattern_stats["rate"],
                   color=bar_colors, alpha=0.85, edgecolor="white")
    for bar, row in zip(bars, pattern_stats.itertuples()):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                f"{row.rate:.0f}%", va="center", fontsize=9)
    ax.set_title("우회 패턴별 탐지율", fontweight="bold")
    ax.set_xlabel("Detection Rate (%)")
    ax.set_xlim(0, 120)
    ax.axvline(x=80, color="gray", linestyle="--", alpha=0.5)

    # ── 그래프 6: 우회 시도 요약 파이 ────────────────────
    ax = axes[1][2]
    detected_n = df_ev["detected"].sum()
    bypassed_n = len(df_ev) - detected_n
    wedge_colors = ["#E24B4A", "#639922"]
    wedges, texts, autotexts = ax.pie(
        [detected_n, bypassed_n],
        labels=["탐지됨", "우회 성공"],
        colors=wedge_colors,
        autopct="%1.1f%%",
        startangle=90,
        wedgeprops={"edgecolor": "white", "linewidth": 2}
    )
    for at in autotexts:
        at.set_fontsize(11)
        at.set_fontweight("bold")
    ax.set_title(f"우회 시도 결과\n(총 {len(df_ev)}개)", fontweight="bold")

    plt.tight_layout()
    plt.savefig("redteam_report.png", dpi=150, bbox_inches="tight")
    print("\n시각화 저장: redteam_report.png")
    plt.show()


# ─────────────────────────────────────────────────────────
# 실행
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    # 1단계: 데이터셋 검증
    df_res, metrics = run_dataset_validation()

    # 2단계: 우회 패턴 테스트
    df_ev = run_evasion_test()

    # 3단계: 시각화
    draw_graphs(df_res, metrics, df_ev)

    print("\n" + "="*60)
    print("레드팀 테스트 완료!")
    print(f"  데이터셋 F1 Score : {metrics['F1 Score']:.4f}")
    print(f"  우회 패턴 탐지율  : {df_ev['detected'].mean()*100:.1f}%")
    print("="*60)