import json



import os



import re



import time



import uuid



from datetime import datetime



from pathlib import Path







import requests



from flask import Flask, Response, jsonify, make_response, redirect, render_template, request, stream_with_context, url_for







from checker import DEFAULT_LIVE_TARGETS, check_live_targets, check_site, check_site_steps



from storage import Storage







BASE_DIR = Path(__file__).resolve().parent



VISITOR_COOKIE = "checkup_vid"



OWNER_NAME = os.environ.get("CHECKUP_OWNER", "Moacir")



CONTACT_EMAIL = os.environ.get("CHECKUP_CONTATO", "moacirsistemax@gmail.com")



PIX_KEY = os.environ.get("CHECKUP_PIX_KEY", "moacirsistemax@gmail.com")



LIVE_TTL_SECONDS = 45



EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")











def _parse_live_targets() -> list[dict]:



    raw_json = os.environ.get("CHECKUP_LIVE_TARGETS", "").strip()



    if raw_json:



        try:



            parsed = json.loads(raw_json)



            if isinstance(parsed, list) and parsed:



                return parsed



        except Exception:



            pass



    return DEFAULT_LIVE_TARGETS











def create_app(



    base_dir: Path = BASE_DIR,



    site_checker=check_site,



    site_step_checker=check_site_steps,



    live_checker=check_live_targets,



) -> Flask:



    app = Flask(__name__)



    store = Storage(Path(base_dir))



    live_targets = _parse_live_targets()



    live_cache = {"ts": 0.0, "items": []}







    def get_live_status(force: bool = False) -> list[dict]:



        now = time.monotonic()



        if force or not live_cache["items"] or (now - live_cache["ts"]) > LIVE_TTL_SECONDS:



            try:



                live_cache["items"] = live_checker(live_targets)



                live_cache["ts"] = now



            except Exception:



                app.logger.exception("Falha ao consultar alvos ao vivo")



        return live_cache["items"]







    @app.context_processor



    def inject_globals():



        return {



            "owner": OWNER_NAME,



            "year": datetime.now().year,



            "stats": store.get_stats(),



            "pix_key": PIX_KEY,



        }







    def render_home(**kwargs):



        context = {



            "result": None,



            "comparison": None,



            "error": None,



            "url": "",



            "waitlist_ok": False,



            "waitlist_error": None,



            "live_targets": get_live_status(force=False),
            "live_items": get_live_status(force=False),



        }



        context.update(kwargs)



        return render_template("index.html", **context)







    @app.route("/", methods=["GET", "POST"])



    def index():



        if request.method == "GET":



            visitor_id = request.cookies.get(VISITOR_COOKIE)



            new_id = None



            if not visitor_id:



                visitor_id = uuid.uuid4().hex



                new_id = visitor_id



            try:



                store.record_page_view(new_id)



            except Exception:



                app.logger.exception("Falha ao registrar visita")







            response = make_response(render_home())



            response.set_cookie(



                VISITOR_COOKIE, visitor_id,



                max_age=60 * 60 * 24 * 365 * 2, httponly=True, samesite="Lax",



            )



            return response







        url = request.form.get("url", "").strip()



        try:



            checked = site_checker(url)



            comp = store.record_and_compare_history(checked)



            return render_home(result=checked, comparison=comp, url=url)



        except ValueError as exc:



            return render_home(error=str(exc), url=url)



        except requests.RequestException:



            return render_home(



                error="Não consegui acessar esse site. Confira o endereço e tente de novo.",



                url=url,



            )



        except Exception:



            app.logger.exception("Falha ao verificar %s", url)



            return render_home(



                error="Algo deu errado ao verificar este site. Tente novamente em instantes.",



                url=url,



            )







    



    @app.route("/.well-known/appspecific/com.chrome.devtools.json", methods=["GET"])



    def chrome_devtools_well_known():



        return ("", 204)







    @app.route("/status/ao-vivo")



    def status_ao_vivo():



        force = request.args.get("force") == "1"



        return jsonify({"items": get_live_status(force=force)})







    @app.route("/verificar/stream", methods=["POST"])



    def verificar_stream():



        payload = request.get_json(silent=True) or {}



        url = str(payload.get("url") or request.form.get("url") or "").strip()







        @stream_with_context



        def generate():



            try:



                for event in site_step_checker(url):



                    if event.get("type") == "done":



                        checked = event["result"]



                        comp = store.record_and_compare_history(checked)



                        rendered_html = render_template(



                            "_resultado.html",



                            result=checked,



                            comparison=comp,



                        )



                        line = json.dumps({



                            "type": "done",



                            "html": rendered_html,



                        }, ensure_ascii=False)



                        yield line + "\n"



                    else:



                        yield json.dumps(event, ensure_ascii=False) + "\n"



            except ValueError as exc:



                yield json.dumps({"type": "error", "message": str(exc)}, ensure_ascii=False) + "\n"



            except requests.RequestException:



                yield json.dumps({



                    "type": "error",



                    "message": "Não consegui acessar esse site. Confira o endereço e tente de novo.",



                }, ensure_ascii=False) + "\n"



            except Exception:



                app.logger.exception("Falha no stream ao verificar %s", url)



                yield json.dumps({



                    "type": "error",



                    "message": "Algo deu errado ao verificar este site. Tente novamente em instantes.",



                }, ensure_ascii=False) + "\n"







        return Response(generate(), mimetype="application/x-ndjson; charset=utf-8")







    @app.route("/avisar", methods=["POST"])



    def avisar():



        email = request.form.get("email", "").strip().lower()



        if not EMAIL_RE.match(email):



            return render_home(waitlist_error="Digite um e-mail válido.")



        store.add_waitlist_email(email)



        return render_home(waitlist_ok=True)







    @app.route("/privacidade")



    def privacidade():



        return render_template(



            "privacidade.html",



            contact=CONTACT_EMAIL,



            updated=datetime.now().strftime("%d/%m/%Y"),



        )







    @app.route("/favicon.ico")



    def favicon():



        return redirect(url_for("static", filename="favicon.svg"), code=301)







    @app.errorhandler(404)



    def not_found(_):



        return render_template(



            "erro.html", code=404,



            message="A página que você procura não existe ou foi movida.",



        ), 404







    @app.errorhandler(500)



    def server_error(_):



        return render_template(



            "erro.html", code=500,



            message="Algo deu errado do nosso lado. Tente novamente em instantes.",



        ), 500







    return app











app = create_app()







if __name__ == "__main__":



    app.run(debug=True)