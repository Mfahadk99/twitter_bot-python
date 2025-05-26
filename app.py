import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from starlette.staticfiles import StaticFiles

app = FastAPI()


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

@app.get("/dexscreener.txt")
def get_dexscreener_file():
    try:
        file_path = os.path.join(STATIC_DIR, "dexscreener_response.txt")
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Dexscreener file not found")
        return FileResponse(file_path, media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")


@app.get("/rugcheck.txt")
def get_rug_file():
    try:
        file_path = os.path.join(STATIC_DIR, "rugcheck_response.txt")
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Rugcheck file not found")
        return FileResponse(file_path, media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")