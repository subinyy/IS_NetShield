# 🛡️ IS_NetShield
### 지능형 유해 URL 실시간 탐지 시스템

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/XGBoost-ML Model-FF6600?style=for-the-badge&logo=xgboost&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-Serving-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/AWS-Deploy-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white"/>
  <img src="https://img.shields.io/badge/React-Dashboard-61DAFB?style=for-the-badge&logo=react&logoColor=black"/>
</p>

<p align="center">
  악성 URL을 머신러닝으로 실시간 분석·차단하는 보안 시스템
</p>

---

## 🔄 시스템 파이프라인

```mermaid
flowchart LR
    A([🌐 URL 입력]) --> B[/피처 추출\nfeature_engineering.py/]
    
    B --> C1[URL 길이 계산]
    B --> C2[특수문자 분석]
    B --> C3[도메인 분석]
    B --> C4[키워드 탐지]

    C1 & C2 & C3 & C4 --> D[(21개 피처 벡터)]

    D --> E[🤖 XGBoost 모델\ntrain_model.py]

    E --> F{예측 결과}
    F -->|✅ 정상| G[benign]
    F -->|⚠️ 피싱| H[phishing]
    F -->|☠️ 악성코드| I[malware]
    F -->|🔨 변조| J[defacement]

    E --> K[📊 성능 평가\nmodel_evaluation.png]
    E --> L[📋 벤치마크\nbenchmark_results.csv]

    style A fill:#4CAF50,color:#fff
    style E fill:#FF6600,color:#fff
    style F fill:#2196F3,color:#fff
    style G fill:#4CAF50,color:#fff
    style H fill:#FF9800,color:#fff
    style I fill:#F44336,color:#fff
    style J fill:#9C27B0,color:#fff
```

---

## 🗂️ 프로젝트 구조

```
IS_NetShield/
├── 📁 src/
│   ├── 🔧 feature_engineering.py   # URL → 피처 추출
│   └── 🤖 train_model.py           # XGBoost 학습 및 평가
├── 📁 data_mal/
│   ├── 📄 malicious_phish.csv      # 정상/악성 혼합 URL 데이터셋 (Kaggle), 사용
│   └── 📄 online-valid.csv         # 악성 URL 데이터셋 (phsing tank), 필요시 비교 검증에 사용예정
├── 📁 model/
│   └── 💾 xgb_model.pkl            # 학습된 모델
├── 📁 results/
│   ├── 📊 model_evaluation.png     # 모델 평가 결과 시각화
│   └── 📋 benchmark_results.csv   # 성능 비교 결과
├── 🚫 .gitignore
└── 📖 README.md
```

---

## 🚀 시작하기

### 1️⃣ 패키지 설치

```bash
pip install xgboost scikit-learn pandas numpy matplotlib seaborn requests
```

### 2️⃣ 데이터셋 다운로드

Kaggle에서 `malicious_phish.csv` 다운로드:  
🔗 https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

> 컬럼: `url`, `type` (benign / phishing / malware / defacement)

### 3️⃣ 피처 추출 확인

```bash
python 1_feature_engineering.py
```

### 4️⃣ 모델 학습

```bash
# 실제 데이터 사용 시 train_model.py 상단 load_sample_data() → load_dataset() 교체
python 2_train_model.py
```
<img width="1787" height="736" alt="model_evaluation" src="https://github.com/user-attachments/assets/d0d060f0-657e-4856-8f26-2811d26ddea0" />

### 5️⃣ 벤치마크 실행 (API 키 선택사항)

```bash
export GOOGLE_SAFE_BROWSING_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
python 3_benchmark.py
```

---

## 🧪 추출 피처 목록 (21개)

| 카테고리 | 피처 |
|:-------:|------|
| 📏 **URL 길이** | `url_length`, `domain_length`, `path_length`, `query_length` |
| 🔣 **특수문자** | `count_dots`, `count_hyphens`, `count_at`, `count_percent` 등 |
| 🌍 **도메인** | `subdomain_depth`, `has_ip_address`, `tld_risk` |
| 🔒 **프로토콜** | `is_https` |
| 🔍 **키워드** | `has_phishing_keyword`, `has_brand_keyword` |
| 🧩 **패턴** | `has_typosquatting`, `has_double_slash` |
| 📐 **통계** | `url_entropy`, `digit_ratio`, `path_depth` |

---

## ⚖️ 비교 대상(Additional)

| 모델 | 특징 | 유형 |
|:----:|------|:----:|
| 🥇 **우리 모델** | XGBoost + 21개 피처 엔지니어링, 로컬 추론 | Local ML |
| 🔵 **Google Safe Browsing** | 업계 표준, 무료 API | Cloud API |
| 🟠 **VirusTotal** | 70개 엔진 앙상블, 정답지로 활용 | Cloud API |

---

## 🗺️ 개발 로드맵

```
✅ 1단계  ML 모델 학습 및 평가
🔄 2단계  4_api_server.py      — FastAPI 서빙
⏳ 3단계  5_aws_deploy/        — EC2 + ALB + WAF 배포
⏳ 4단계  6_ui/                — React 대시보드
```

---

<p align="center">
  <sub>🔐 보안 프로젝트 | Information Security Class</sub>
</p>
