"""
IS_NetShield - 데이터 전처리 모듈
Author: Yongseon
Description: malicious_phish.csv를 학습 가능한 형태로 정제
"""

import pandas as pd
import numpy as np
import re
from pathlib import Path

# 재현성을 위한 시드 고정
RANDOM_STATE = 42

INPUT_PATH = "/mnt/user-data/uploads/malicious_phish.csv"
PHISHTANK_PATH = "/mnt/user-data/uploads/online-valid.csv"
OUTPUT_DIR = Path("/home/claude/data_mal")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_data(path):
    """원본 CSV 로드"""
    df = pd.read_csv(path)
    print(f"[1] 원본 로드 완료: {df.shape[0]:,}행 × {df.shape[1]}열")
    return df


def clean_urls(df):
    """URL 정제: 공백 제거, 소문자 통일, 빈 문자열 제거"""
    before = len(df)
    df['url'] = df['url'].astype(str).str.strip()
    df['url'] = df['url'].str.replace(r'\s+', '', regex=True)  # 내부 공백도 제거
    df = df[df['url'].str.len() > 0]
    df = df[df['url'].str.lower() != 'nan']
    print(f"[2] URL 정제: {before:,} → {len(df):,} (제거: {before - len(df):,})")
    return df


def remove_duplicates(df):
    """중복 URL 제거 (같은 URL이 다른 라벨로 있을 경우 더 위험한 라벨 우선)"""
    before = len(df)
    # 위험도 우선순위: malware > phishing > defacement > benign
    priority = {'malware': 0, 'phishing': 1, 'defacement': 2, 'benign': 3}
    df['_priority'] = df['type'].map(priority)
    df = df.sort_values('_priority').drop_duplicates(subset=['url'], keep='first')
    df = df.drop(columns=['_priority'])
    print(f"[3] 중복 제거: {before:,} → {len(df):,} (제거: {before - len(df):,})")
    return df


def filter_url_length(df, min_len=4, max_len=500):
    """비정상적 URL 길이 필터링 (너무 짧거나 너무 긴 URL은 노이즈 가능성 높음)"""
    before = len(df)
    url_len = df['url'].str.len()
    df = df[(url_len >= min_len) & (url_len <= max_len)]
    print(f"[4] 길이 필터({min_len}~{max_len}자): {before:,} → {len(df):,} (제거: {before - len(df):,})")
    return df


def validate_url_format(df):
    """비정상 문자가 포함되거나 한글/제어문자가 섞인 URL 제거"""
    before = len(df)
    # 인쇄 가능한 ASCII 문자만 허용 (URL은 본질적으로 ASCII)
    valid_pattern = re.compile(r'^[\x21-\x7E]+$')
    mask = df['url'].apply(lambda x: bool(valid_pattern.match(x)))
    df = df[mask]
    print(f"[5] URL 형식 검증: {before:,} → {len(df):,} (제거: {before - len(df):,})")
    return df


def map_to_three_classes(df):
    """
    4클래스 → 3클래스 매핑 (IS_NetShield 정책에 맞춤)
    - benign → allow (정상)
    - defacement → alert (경고: 변조된 페이지지만 즉시 위험은 낮음)
    - phishing, malware → block (위험: 즉시 차단 필요)
    """
    label_map = {
        'benign': 'allow',
        'defacement': 'alert',
        'phishing': 'block',
        'malware': 'block',
    }
    df['label'] = df['type'].map(label_map)
    
    # 정수형 라벨도 추가 (XGBoost 학습용)
    label_id = {'allow': 0, 'alert': 1, 'block': 2}
    df['label_id'] = df['label'].map(label_id)
    
    print(f"[6] 라벨 매핑 완료 (4클래스 → 3클래스)")
    print(df['label'].value_counts().to_string())
    return df


def balance_classes(df, target_per_class=None, random_state=RANDOM_STATE):
    """
    클래스 불균형 완화: 다수 클래스(allow)를 다운샘플링
    원본은 allow가 약 65%를 차지해 모델이 정상으로만 예측해도 정확도가 높아 보이는 문제 발생
    """
    counts = df['label'].value_counts()
    if target_per_class is None:
        # 가장 적은 클래스의 1.5배를 기준으로 다운샘플링 (완전 균형보다 약간 자연스럽게)
        target_per_class = int(counts.min() * 1.5)
    
    balanced_parts = []
    for label, group in df.groupby('label'):
        n = min(len(group), target_per_class)
        balanced_parts.append(group.sample(n=n, random_state=random_state))
    
    df_bal = pd.concat(balanced_parts, ignore_index=True)
    df_bal = df_bal.sample(frac=1, random_state=random_state).reset_index(drop=True)  # 셔플
    
    print(f"[7] 클래스 밸런싱 (클래스당 최대 {target_per_class:,}개)")
    print(df_bal['label'].value_counts().to_string())
    return df_bal


def load_phishtank(path):
    """
    PhishTank online-valid.csv 로드 및 정제
    - 모든 항목이 verified=yes, online=yes로 검증된 실시간 피싱 URL
    - 외부 검증셋(holdout)으로 사용 → block 라벨로 통일
    """
    df_pt = pd.read_csv(path)
    df_pt = df_pt[['url']].copy()
    df_pt['url'] = df_pt['url'].astype(str).str.strip()
    df_pt = df_pt[df_pt['url'].str.len() > 0]

    # 메인셋과 동일한 정제 기준 적용
    df_pt = df_pt.drop_duplicates(subset=['url'])
    url_len = df_pt['url'].str.len()
    df_pt = df_pt[(url_len >= 4) & (url_len <= 500)]
    valid_pattern = re.compile(r'^[\x21-\x7E]+$')
    df_pt = df_pt[df_pt['url'].apply(lambda x: bool(valid_pattern.match(x)))]

    # 전부 검증된 피싱이므로 block(=2)으로 라벨링
    df_pt['type'] = 'phishing'
    df_pt['label'] = 'block'
    df_pt['label_id'] = 2

    print(f"[PT-1] PhishTank 정제 완료: {len(df_pt):,}건 (전부 block)")
    return df_pt.reset_index(drop=True)


def remove_leakage(df_main, df_pt):
    """
    데이터 누수 제거: PhishTank에 있는 URL은 메인 학습셋에서 제거
    PhishTank를 외부 검증셋으로 쓰려면 학습셋에 절대 포함되면 안 됨
    """
    before = len(df_main)
    pt_urls = set(df_pt['url'])
    df_main = df_main[~df_main['url'].isin(pt_urls)]
    print(f"[PT-2] PhishTank 누수 제거: {before:,} → {len(df_main):,} (제거: {before - len(df_main):,})")
    return df_main


def split_train_test(df, test_ratio=0.2, random_state=RANDOM_STATE):
    """학습/테스트 분할 (계층 샘플링으로 클래스 비율 유지)"""
    from sklearn.model_selection import train_test_split
    train_df, test_df = train_test_split(
        df,
        test_size=test_ratio,
        stratify=df['label'],
        random_state=random_state,
    )
    print(f"[8] 학습/테스트 분할: train={len(train_df):,}, test={len(test_df):,}")
    return train_df.reset_index(drop=True), test_df.reset_index(drop=True)


def main():
    print("=" * 60)
    print("IS_NetShield 데이터 전처리 시작")
    print("=" * 60)

    # ---- 메인 데이터셋 (Kaggle) ----
    df = load_data(INPUT_PATH)
    df = clean_urls(df)
    df = remove_duplicates(df)
    df = filter_url_length(df)
    df = validate_url_format(df)
    df = map_to_three_classes(df)

    # ---- PhishTank 외부 검증셋 ----
    df_pt = load_phishtank(PHISHTANK_PATH)

    # 데이터 누수 방지: PhishTank URL은 학습셋에서 제거
    df = remove_leakage(df, df_pt)

    # ---- 학습셋 밸런싱 및 분할 ----
    df_bal = balance_classes(df)
    train_df, test_df = split_train_test(df_bal)

    # 저장
    full_path = OUTPUT_DIR / "malicious_phish_clean.csv"
    train_path = OUTPUT_DIR / "train.csv"
    test_path = OUTPUT_DIR / "test.csv"
    holdout_path = OUTPUT_DIR / "phishtank_holdout.csv"

    df_bal[['url', 'type', 'label', 'label_id']].to_csv(full_path, index=False)
    train_df[['url', 'type', 'label', 'label_id']].to_csv(train_path, index=False)
    test_df[['url', 'type', 'label', 'label_id']].to_csv(test_path, index=False)
    df_pt[['url', 'type', 'label', 'label_id']].to_csv(holdout_path, index=False)

    print("\n" + "=" * 60)
    print("저장 완료")
    print("=" * 60)
    print(f"  - 전체 정제본:       {full_path}")
    print(f"  - 학습셋:           {train_path}")
    print(f"  - 테스트셋:         {test_path}")
    print(f"  - PhishTank 검증셋: {holdout_path}")


if __name__ == "__main__":
    main()
