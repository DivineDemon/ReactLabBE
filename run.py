from app import create_app
from asgiref.wsgi import WsgiToAsgi

app = create_app()
asgi_app = WsgiToAsgi(app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("run:asgi_app", host="127.0.0.1", port=8000, log_level="info")
