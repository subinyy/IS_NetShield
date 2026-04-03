# 지능형 유해 URL 실시간 탐지 시스템

## 프로젝트 구조

```
url_detection/
├── 1_feature_engineering.py   # URL → 피처 추출
├── 2_train_model.py           # XGBoost 학습 + 평가
├── 3_benchmark.py             # --경쟁 모델과 성능 비교-- 취소 
├── model/
│   └── xgb_model.pkl          # 학습된 모델 (자동 생성)
└── results/
    ├── model_evaluation.png   # confusion matrix + feature importance
    └── benchmark_results.csv  # 비교 실험 결과
```

## 시작하기

### 1) 패키지 설치
```bash
pip install xgboost scikit-learn pandas numpy matplotlib seaborn requests
```

### 2) 데이터셋 다운로드
Kaggle에서 `malicious_phish.csv` 다운로드:
https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

컬럼: `url`, `type` (benign / phishing / malware / defacement)

### 3) 피처 추출 확인
```bash
python 1_feature_engineering.py
```

### 4) 모델 학습
```bash
# 실제 데이터 사용 시 train_model.py 상단 load_sample_data() → load_dataset() 교체
python 2_train_model.py
```

### 5) 벤치마크 (API 키 선택사항)
```bash
export GOOGLE_SAFE_BROWSING_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
python 3_benchmark.py
```

## 추출 피처 목록 (21개)

| 카테고리 | 피처 |
|---------|------|
| URL 길이 | url_length, domain_length, path_length, query_length |
| 특수문자 | count_dots, count_hyphens, count_at, count_percent 등 |
| 도메인 | subdomain_depth, has_ip_address, tld_risk |
| 프로토콜 | is_https |
| 키워드 | has_phishing_keyword, has_brand_keyword |
| 패턴 | has_typosquatting, has_double_slash |
| 통계 | url_entropy, digit_ratio, path_depth |

## 비교 대상

| 모델 | 특징 |
|------|------|
| **우리 모델** | XGBoost + 피처 엔지니어링, 로컬 추론 |
| Google Safe Browsing | 업계 표준, 무료 API |
| VirusTotal | 70개 엔진 앙상블, 정답지로 활용 |

## 다음 단계

- `4_api_server.py` — FastAPI 서빙 (2단계)
- `5_aws_deploy/` — EC2 + ALB + WAF 배포 (3단계)
- `6_ui/` — React 대시보드 (최종)
