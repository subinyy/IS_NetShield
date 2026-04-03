"""
PhishTank 최신 피싱 URL 데이터 다운로드
저장 위치: online-valid.csv (프로젝트 폴더)
"""

import requests
import pandas as pd

def download_phishtank(save_path="online-valid.csv"):
    print("PhishTank 다운로드 중... (수십 초 걸릴 수 있어요)")
    url = "http://data.phishtank.com/data/online-valid.csv"
    headers = {"User-Agent": "phishtank/myapp"}

    r = requests.get(url, headers=headers, timeout=60)
    r.raise_for_status()

    with open(save_path, "wb") as f:
        f.write(r.content)

    # 다운로드 확인
    df = pd.read_csv(save_path)
    print(f"\n다운로드 완료: {save_path}")
    print(f"총 피싱 URL: {len(df):,}개")
    print(f"\n컬럼 목록: {list(df.columns)}")
    print(f"\n샘플 5개:")
    print(df.head())

if __name__ == "__main__":
    download_phishtank()