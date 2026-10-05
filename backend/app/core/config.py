from pydantic import BaseModel
import os


def _b(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in {"1", "true", "yes", "on"}


class Settings(BaseModel):
    app_name: str = "AegisAI"
    environment: str = os.getenv("AEGIS_ENV", "development")
    database_url: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./aegis.db")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    kafka_bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    kafka_enabled: bool = _b("KAFKA_ENABLED")
    redis_enabled: bool = _b("REDIS_ENABLED")
    threat_score_alert_threshold: int = int(os.getenv("THREAT_SCORE_ALERT_THRESHOLD", "70"))

    jwt_secret: str = os.getenv("JWT_SECRET", "dev-only-change-me-before-production")
    access_token_minutes: int = int(os.getenv("ACCESS_TOKEN_MINUTES", "480"))
    admin_username: str = os.getenv("AEGIS_ADMIN_USER", "admin")
    admin_password: str = os.getenv("AEGIS_ADMIN_PASSWORD", "aegis-demo")
    analyst_username: str = os.getenv("AEGIS_ANALYST_USER", "analyst")
    analyst_password: str = os.getenv("AEGIS_ANALYST_PASSWORD", "analyst-demo")

    oidc_enabled: bool = _b("OIDC_ENABLED")
    oidc_issuer: str = os.getenv("OIDC_ISSUER", "")
    oidc_client_id: str = os.getenv("OIDC_CLIENT_ID", "")
    oidc_jwks_url: str = os.getenv("OIDC_JWKS_URL", "")

    misp_url: str = os.getenv("MISP_URL", "")
    misp_api_key: str = os.getenv("MISP_API_KEY", "")
    misp_verify_tls: bool = _b("MISP_VERIFY_TLS", "true")
    taxii_discovery_url: str = os.getenv("TAXII_DISCOVERY_URL", "")
    taxii_collection_url: str = os.getenv("TAXII_COLLECTION_URL", "")
    taxii_username: str = os.getenv("TAXII_USERNAME", "")
    taxii_password: str = os.getenv("TAXII_PASSWORD", "")

    evidence_backend: str = os.getenv("EVIDENCE_BACKEND", "local")  # local|s3
    evidence_local_dir: str = os.getenv("EVIDENCE_LOCAL_DIR", "/data/evidence")
    s3_endpoint_url: str = os.getenv("S3_ENDPOINT_URL", "")
    s3_access_key: str = os.getenv("S3_ACCESS_KEY", "")
    s3_secret_key: str = os.getenv("S3_SECRET_KEY", "")
    s3_bucket: str = os.getenv("S3_BUCKET", "aegis-evidence")
    s3_region: str = os.getenv("S3_REGION", "us-east-1")

    soar_provider: str = os.getenv("SOAR_PROVIDER", "disabled")  # disabled|cloudflare|crowdstrike|msgraph
    cloudflare_api_token: str = os.getenv("CLOUDFLARE_API_TOKEN", "")
    cloudflare_account_id: str = os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
    crowdstrike_client_id: str = os.getenv("CROWDSTRIKE_CLIENT_ID", "")
    crowdstrike_client_secret: str = os.getenv("CROWDSTRIKE_CLIENT_SECRET", "")
    crowdstrike_base_url: str = os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
    msgraph_access_token: str = os.getenv("MSGRAPH_ACCESS_TOKEN", "")

    prometheus_enabled: bool = _b("PROMETHEUS_ENABLED", "true")

    neo4j_enabled: bool = _b("NEO4J_ENABLED", "true")
    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
    neo4j_user: str = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("NEO4J_PASSWORD", "aegis-graph-change-me")
    kafka_raw_topic: str = os.getenv("KAFKA_RAW_TOPIC", "aegis.raw.events")
    kafka_consumer_group: str = os.getenv("KAFKA_CONSUMER_GROUP", "aegis-detection-v1")
    otel_enabled: bool = _b("OTEL_ENABLED", "true")
    otel_endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318/v1/traces")


settings = Settings()
