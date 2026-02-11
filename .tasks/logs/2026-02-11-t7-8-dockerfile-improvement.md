# T7.8: Dockerfile Multi-Stage Build 개선

**날짜**: 2026-02-11
**담당**: implementer
**예상 소요**: 1.5h
**실제 소요**: 15분
**상태**: ✅ 완료

## 개요
기존 2-stage Dockerfile을 cargo-chef를 활용한 4-stage 빌드로 개선하여 의존성 캐싱을 최적화하고, OCI 이미지 레이블과 HEALTHCHECK를 추가했습니다.

## 구현 내용

### 1. 4-Stage Multi-Stage Build

#### Stage 1: Planner
- `lukemathwalker/cargo-chef:latest-rust-1` 이미지 사용
- `cargo chef prepare`로 의존성 레시피 추출
- recipe.json 생성 (의존성 메타데이터만 포함)

#### Stage 2: Cacher
- `cargo chef cook --release`로 의존성만 사전 빌드
- 소스 코드 변경 시에도 이 레이어는 캐시 유지
- 빌드 시간 대폭 단축 (의존성 재컴파일 불필요)

#### Stage 3: Builder
- `rust:1-bookworm` 공식 이미지 사용
- Cacher 단계의 컴파일 결과물(target/) 복사
- 소스 코드만 복사하여 애플리케이션 빌드
- 의존성은 이미 컴파일되어 있으므로 빠른 빌드

#### Stage 4: Runtime
- `debian:bookworm-slim` 최소 이미지 사용 (약 80MB)
- 런타임 의존성만 설치 (ca-certificates, libssl3)
- 비루트 사용자 (ironpost:ironpost) 실행
- 최소 권한 원칙 적용

### 2. .dockerignore 생성
```text
# 빌드 아티팩트
target/

# Git
.git/

# 문서
docs/, *.md

# 태스크 및 기획
.tasks/, .claude/, .knowledge/, .reviews/

# GitHub workflows
.github/

# 환경 파일
.env, .env.*

# Docker compose 파일
docker-compose*.yml

# IDE/OS
.vscode/, .idea/, .DS_Store

# 임시 파일
tmp/, *.tmp, *.bak
```

### 3. OCI 이미지 레이블 추가
```dockerfile
LABEL maintainer="Ironpost Project <noreply@example.com>"
LABEL version="0.1.0"
LABEL description="Ironpost - Integrated Security Monitoring Platform"
LABEL org.opencontainers.image.title="Ironpost"
LABEL org.opencontainers.image.description="eBPF-based network detection, log analysis, container isolation, and SBOM vulnerability scanning"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.vendor="Ironpost Project"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/dongwonkwak/ironpost"
```

### 4. HEALTHCHECK 추가
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ironpost-cli status --format json > /dev/null || exit 1
```

- `ironpost-cli status` 명령으로 데몬 프로세스 상태 확인
- 30초 간격으로 헬스 체크
- 10초 타임아웃
- 초기 시작 후 5초 대기 (grace period)
- 3회 연속 실패 시 unhealthy 판단

### 5. 보안 강화
- 비루트 사용자(ironpost) 실행
- 최소 권한 디렉토리 (755)
- 런타임 의존성 최소화
- 불필요한 파일 제외 (.dockerignore)

## 변경 파일
1. `docker/Dockerfile` -- 4-stage 빌드로 개선 (36줄 → 79줄)
2. `.dockerignore` -- 신규 생성 (58줄)

## 주요 개선 사항

### 빌드 캐싱 최적화
- **Before**: 소스 코드 한 줄 변경 → 전체 의존성 재컴파일
- **After**: 소스 코드 변경 → 의존성은 캐시 사용, 애플리케이션만 재컴파일
- **예상 효과**: 재빌드 시간 50-70% 단축

### 이미지 크기
- **Base**: debian:bookworm-slim (약 80MB)
- **Runtime**: ca-certificates + libssl3 추가 (약 10MB)
- **Binaries**: ironpost-daemon + ironpost-cli (약 40MB, release build)
- **예상 총 크기**: 약 130MB (압축)

### 보안 베스트 프랙티스
- ✅ 비루트 사용자 실행
- ✅ 최소 권한 디렉토리
- ✅ 최소 베이스 이미지 (slim variant)
- ✅ 런타임 의존성 최소화
- ✅ 멀티 스테이지 빌드 (빌드 도구 제외)
- ✅ HEALTHCHECK 추가
- ✅ OCI 메타데이터 레이블

## Acceptance Criteria 검증

- [x] cargo-chef를 사용한 4-stage 빌드 구조
- [x] .dockerignore로 불필요한 파일 제외
- [x] HEALTHCHECK 명령 동작 (`ironpost-cli status`)
- [x] LABEL 메타데이터 포함 (OCI 표준)
- [x] 비루트 사용자 (ironpost) 유지
- [x] 기존 ENTRYPOINT/CMD 로직 유지

## 다음 단계
T7.9에서 docker-compose.yml을 개선하여:
- 서비스별 healthcheck 추가
- 리소스 제한 설정
- 네트워크 격리
- 환경변수 오버라이드

## 참조
- Cargo Chef: https://github.com/LukeMathWalker/cargo-chef
- OCI Image Spec: https://github.com/opencontainers/image-spec/blob/main/annotations.md
- Docker Best Practices: https://docs.docker.com/develop/dev-best-practices/
