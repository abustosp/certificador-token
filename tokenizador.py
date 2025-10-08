import os
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
import base64

import requests
from dotenv import load_dotenv


def load_env():
    load_dotenv(override=True)

    api_url = os.getenv("CERTIFICADO_API_URL")
    if not api_url:
        print("❌ Falta la variable API_URL en el .env", file=sys.stderr)
        sys.exit(1)

    timeout = int(os.getenv("TIMEOUT", "30"))
    output_dir = os.getenv("DIRECTORIO_SALIDA", ".")
    output_file = os.getenv("ARCHIVO_SALIDA", f"response_{timestamp_str()}.json")     

    # Construir payload desde DATA_*
    payload = {}

    # Construir headers desde HEADER_* (se respeta mayúsc/minusc del nombre final)
    headers = {"Content-Type": "application/json"
               }  # Content-Type por defecto
    
    # Leer el archivo base64 del certificado si está definido
    certificado = os.getenv("CERTIFICADO")
    directorio_certificado = os.getenv("DIRECTORIO_CERTIFICADO", ".")

    certificado_b64 = None
    if certificado:
        cert_full_path = os.path.join(directorio_certificado, certificado)
        try:
            with open(cert_full_path, "rb") as f:
                certificado_b64 = base64.b64encode(f.read()).decode("utf-8")
        except Exception as e:
            print(f"❌ No se pudo leer el certificado en {cert_full_path}: {e}", file=sys.stderr)
            sys.exit(1)

    llave = os.getenv("LLAVE_PRIVADA")
    directorio_llave = os.getenv("LLAVE_DIRECTORIO")
    
    llave_b64 = None
    if llave:
        llave_full_path = os.path.join(directorio_llave, llave)
        try:
            with open(llave_full_path, "rb") as f:
                llave_b64 = base64.b64encode(f.read()).decode("utf-8")
        except Exception as e:
            print(f"❌ No se pudo leer la llave en {llave_full_path}: {e}", file=sys.stderr)
            sys.exit(1)

    params = {
        "email": os.getenv("MAIL"),
        "api_key": os.getenv("API_KEY"),
        "cuit_representante": os.getenv("CUIT_REPRESENTANTE"),
        "certificado": certificado_b64,
        "llave_privada": llave_b64,
        "servicio_id": os.getenv("SERVICIO_ARCA"),
        "testing": os.getenv("TESTING"),
        "cn": os.getenv("CN")
    }
    

    return api_url, timeout, output_dir, output_file, payload, headers, params

def timestamp_str():
    # UTC para evitar ambigüedades; si preferís local, cambiá a datetime.now()
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-UTC")

def save_response(output_dir: str, output_file: str, data: str | bytes, is_json_like: bool):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    fpath = os.path.join(output_dir, output_file)

    # Si es JSON, lo dejamos pretty-printed; si no, lo guardamos tal cual
    try:
        if is_json_like:
            parsed = json.loads(data if isinstance(data, (str, bytes, bytearray)) else json.dumps(data))
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump(parsed, f, ensure_ascii=False, indent=2)
        else:
            mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
            with open(fpath, mode) as f:
                f.write(data)
    except Exception as e:
        # Ante un problema serializando, guardamos texto crudo
        with open(fpath, "wb") as f:
            f.write(data if isinstance(data, (bytes, bytearray)) else str(data).encode("utf-8", errors="replace"))
        print(f"⚠️ No se pudo serializar como JSON: {e}. Se guardó crudo.", file=sys.stderr)

    return fpath

def main():
    api_url, timeout, output_dir, output_file, payload, headers, params = load_env()

    # Debug mínimo opcional
    print(f"➡️  POST {api_url}")
    print(f"🧩 Payload (claves): {list(payload.keys())}")
    extra_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
    if extra_headers:
        print(f"📬 Headers extra: {list(extra_headers.keys())}")

    try:
        resp = requests.post(api_url, json=payload, headers=headers, timeout=timeout, params=params)
        # print request
        print(f"➡️  Request: {resp.request.method} {resp.request.url}")
        print(f"📝 Headers: {dict(resp.request.headers)}")
        print(f"📦 Body: {resp.request.body}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de red/SSL/timeout: {e}", file=sys.stderr)
        sys.exit(2)

    # Intentamos parsear JSON (éxito o error)
    content = resp.content
    is_json = False
    try:
        _ = resp.json()
        is_json = True
    except ValueError:
        is_json = False

    fpath = save_response(output_dir, output_file , content, is_json_like=is_json)

    status_info = f"HTTP {resp.status_code}"
    if 200 <= resp.status_code < 300:
        print(f"✅ OK {status_info} — respuesta guardada en: {fpath}")
        sys.exit(0)
    else:
        print(f"❗Respuesta no exitosa ({status_info}). Cuerpo guardado en: {fpath}", file=sys.stderr)
        sys.exit(3)

if __name__ == "__main__":
    main()
