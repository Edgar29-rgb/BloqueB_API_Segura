from fastapi import FastAPI, HTTPException, Header

app = FastAPI(title="Bloque B - API Segura")

reportes = {
    1: {
        "propietario": "Usuario A",
        "descripcion": "Revision BMW"
    },
    2: {
        "propietario": "Usuario B",
        "descripcion": "Revision Lamborghini"
    }
}

@app.get("/")
def inicio():
    return {"mensaje": "API funcionando correctamente"}

@app.get("/reportes/{reporte_id}")
def consultar_reporte(
    reporte_id: int,
    usuario: str = Header(...)
):
    if reporte_id not in reportes:
        raise HTTPException(
            status_code=404,
            detail="Reporte no encontrado"
        )

    reporte = reportes[reporte_id]

    if reporte["propietario"] != usuario:
        raise HTTPException(
            status_code=403,
            detail="Acceso denegado. No tiene permisos."
        )

    return reporte
