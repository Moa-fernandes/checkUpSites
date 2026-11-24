from app import create_app
from storage import Storage


def test_storage_history_comparison(tmp_path):
    store = Storage(tmp_path)
    first = {
        "url": "https://exemplo.com",
        "score": 70,
        "total_issues": 4,
        "metrics": {"ttfb_ms": 500, "ssl_days_left": 90},
    }
    second = {
        "url": "https://exemplo.com",
        "score": 85,
        "total_issues": 2,
        "metrics": {"ttfb_ms": 320, "ssl_days_left": 89},
    }
    assert store.record_and_compare_history(first) is None
    comp = store.record_and_compare_history(second)
    assert comp is not None
    assert comp["score_diff"] == 15
    assert comp["issues_diff"] == -2
    assert comp["ttfb_diff"] == -180
    assert comp["ssl_days_diff"] == -1


def test_flask_routes_and_waitlist(tmp_path):
    def fake_checker(_raw_url):
        return {
            "url": "https://teste.exemplo.com",
            "score": 92,
            "total_issues": 1,
            "metrics": {
                "ttfb_ms": 180,
                "redirects": 0,
                "is_https": True,
                "ssl_days_left": 120,
                "ssl_expires_at": "24/03/2027",
                "ssl_valid": True,
                "checked_links": 5,
                "broken_links": 0,
                "total_images": 2,
                "broken_images": 0,
                "contrast_elements": 10,
                "high_count": 0,
                "medium_count": 1,
                "low_count": 0,
                "infra_count": 1,
                "a11y_count": 0,
                "quality_count": 0,
            },
            "issues": [
                {
                    "level": "media",
                    "category": "Infraestrutura",
                    "title": "Cabeçalhos de segurança HTTP ausentes",
                    "count": 2,
                    "explanation": "Explicação de teste.",
                    "fix": "Configurar cabeçalhos.",
                    "examples": ["HSTS: ajuda a forçar HTTPS."],
                }
            ],
        }

    app = create_app(base_dir=tmp_path, site_checker=fake_checker)
    client = app.test_client()

    resp_get = client.get("/")
    assert resp_get.status_code == 200
    assert "Seu site está em boa forma?" in resp_get.get_data(as_text=True)

    resp_post = client.post("/", data={"url": "teste.exemplo.com"})
    assert resp_post.status_code == 200
    body = resp_post.get_data(as_text=True)
    assert "92" in body
    assert "Baixar JSON" in body

    resp_avisar = client.post("/avisar", data={"email": "dev@exemplo.com"})
    assert resp_avisar.status_code == 200
    assert (tmp_path / "interessados.csv").exists()