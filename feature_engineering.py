"""
1단계: 피처 엔지니어링
URL에서 머신러닝에 사용할 특징값을 추출합니다.
"""

import re
import urllib.parse
from datetime import datetime


def extract_features(url: str) -> dict:
    """URL 하나에서 모든 피처를 추출해서 딕셔너리로 반환"""

    features = {}
    parsed = _safe_parse(url)

    # ── 1. URL 길이 관련 ──────────────────────────────────────
    features["url_length"] = len(url)
    features["domain_length"] = len(parsed.get("domain", ""))
    features["path_length"] = len(parsed.get("path", ""))
    features["query_length"] = len(parsed.get("query", ""))

    # ── 2. 특수문자 개수 ──────────────────────────────────────
    features["count_dots"] = url.count(".")
    features["count_hyphens"] = url.count("-")
    features["count_underscores"] = url.count("_")
    features["count_slashes"] = url.count("/")
    features["count_at"] = url.count("@")           # @ 있으면 매우 의심
    features["count_question"] = url.count("?")
    features["count_equals"] = url.count("=")
    features["count_ampersand"] = url.count("&")
    features["count_percent"] = url.count("%")       # URL 인코딩 과다 사용

    # ── 3. 도메인 분석 ────────────────────────────────────────
    domain = parsed.get("domain", "")
    features["subdomain_depth"] = _count_subdomains(domain)
    features["has_ip_address"] = int(_is_ip_address(domain))
    features["has_www"] = int(domain.startswith("www."))
    features["tld_risk"] = _tld_risk_score(domain)  # 위험 TLD 여부

    # ── 4. 프로토콜 ───────────────────────────────────────────
    features["is_https"] = int(url.startswith("https"))

    # ── 5. 피싱 키워드 탐지 ───────────────────────────────────
    features["has_phishing_keyword"] = int(_has_phishing_keyword(url))
    features["has_brand_keyword"] = int(_has_brand_keyword(url))

    # ── 6. 타이포스쿼팅 탐지 ──────────────────────────────────
    features["has_typosquatting"] = int(_has_typosquatting(domain))

    # ── 7. URL 엔트로피 (난독화 탐지) ────────────────────────
    features["url_entropy"] = _calculate_entropy(url)

    # ── 8. 숫자 비율 ──────────────────────────────────────────
    digit_count = sum(c.isdigit() for c in url)
    features["digit_ratio"] = digit_count / len(url) if url else 0

    # ── 9. 서브디렉토리 깊이 ──────────────────────────────────
    path = parsed.get("path", "")
    features["path_depth"] = path.count("/")

    # ── 10. 더블 슬래시 (리다이렉트 트릭) ────────────────────
    features["has_double_slash"] = int("//" in url[7:])  # https:// 이후

    return features


# ─────────────────────────────────────────────────────────────
# 내부 헬퍼 함수들
# ─────────────────────────────────────────────────────────────

def _safe_parse(url: str) -> dict:
    try:
        parsed = urllib.parse.urlparse(url)
        return {
            "scheme": parsed.scheme,
            "domain": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query,
        }
    except Exception:
        return {"scheme": "", "domain": url, "path": "", "query": ""}


def _count_subdomains(domain: str) -> int:
    """서브도메인 깊이 반환 (www.sub.example.com → 2)"""
    parts = domain.split(".")
    return max(0, len(parts) - 2)


def _is_ip_address(domain: str) -> bool:
    """도메인이 IP 주소인지 확인"""
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(ip_pattern, domain))


def _tld_risk_score(domain: str) -> int:
    """
    TLD 위험 점수 반환
    0: 안전, 1: 주의, 2: 위험
    출처: Spamhaus TLD 악용 통계 기반
    """
    high_risk_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click"}
    medium_risk_tlds = {".info", ".biz", ".online", ".site", ".ru", ".cn"}

    domain_lower = domain.lower()
    if any(domain_lower.endswith(tld) for tld in high_risk_tlds):
        return 2
    if any(domain_lower.endswith(tld) for tld in medium_risk_tlds):
        return 1
    return 0


def _has_phishing_keyword(url: str) -> bool:
    """피싱에서 자주 쓰이는 단어 탐지"""
    keywords = [
        "login", "signin", "sign-in", "secure", "verify", "verification",
        "update", "confirm", "account", "banking", "payment", "password",
        "credential", "authenticate", "webscr", "ebayisapi"
    ]
    url_lower = url.lower()
    return any(kw in url_lower for kw in keywords)


def _has_brand_keyword(url: str) -> bool:
    """정상 브랜드명을 사칭하는지 탐지"""
    brands = [
        "paypal", "apple", "google", "microsoft", "amazon", "facebook",
        "netflix", "instagram", "twitter", "kakao", "naver", "samsung"
    ]
    domain = urllib.parse.urlparse(url).netloc.lower()
    # 공식 도메인이 아닌데 브랜드명이 들어있으면 의심
    for brand in brands:
        if brand in domain:
            official = f"{brand}.com"
            if not domain.endswith(official):
                return True
    return False


def _has_typosquatting(domain: str) -> bool:
    """
    타이포스쿼팅 패턴 탐지
    예: g00gle.com, paypa1.com, arnazon.com
    """
    typo_patterns = [
        r"g[0][o0]gle|g[o][0]gle",
        r"paypa[l1]",
        r"[a4]m[a4]z[o0]n",
        r"f[a4]ceb[o0][o0]k",
        r"micr[o0]s[o0]ft",
        r"[a4]pple",
        r"[n][a4]ver",
        r"k[a4]k[a4][o0]",
    ]
    domain_lower = domain.lower()
    return any(re.search(p, domain_lower) for p in typo_patterns)


def _calculate_entropy(text: str) -> float:
    """
    Shannon 엔트로피 계산
    높을수록 랜덤한 문자열 → 악성 URL 가능성 높음
    """
    import math
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length)
                   for count in freq.values())
    return round(entropy, 4)


# ─────────────────────────────────────────────────────────────
# 실행 테스트
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_urls = [
        ("https://www.google.com", "정상"),
        ("https://www.naver.com/search?q=test", "정상"),
        ("http://paypa1-secure.xyz/login/verify", "피싱"),
        ("http://192.168.1.1/admin/login.php", "의심"),
        ("http://free-gift-amazon.tk/claim?user=1234", "피싱"),
        ("https://g00gle.com/accounts/login", "타이포스쿼팅"),
    ]

    print(f"{'URL':<45} {'레이블':<10} {'길이':>5} {'위험TLD':>7} {'피싱KW':>6} {'타이포':>6} {'IP':>4} {'엔트로피':>8}")
    print("-" * 100)

    for url, label in test_urls:
        f = extract_features(url)
        print(
            f"{url:<45} {label:<10} "
            f"{f['url_length']:>5} "
            f"{f['tld_risk']:>7} "
            f"{f['has_phishing_keyword']:>6} "
            f"{f['has_typosquatting']:>6} "
            f"{f['has_ip_address']:>4} "
            f"{f['url_entropy']:>8}"
        )
