
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, ConfigDict

app = FastAPI(title="Bloque B - Pedidos y Autorizacion")

usuarios = {
    "clave-lab-a": {"id": 1, "nombre": "Usuario A", "rol": "user"},
    "clave-lab-b": {"id": 2, "nombre": "Usuario B", "rol": "user"},
    "clave-lab-admin": {"id": 3, "nombre": "Administrador", "rol": "admin"}
}

pedidos = {
    1: {"id": 1, "owner_id": 1, "articulo": "Computadora", "cantidad": 1},
    2: {"id": 2, "owner_id": 2, "articulo": "Teclado", "cantidad": 2}
}

perfiles = {
    1: {"nombre": "Usuario A"},
    2: {"nombre": "Usuario B"},
    3: {"nombre": "Administrador"}
}

auditoria = [
    {"evento": "Inicio del servicio", "resultado": "OK"}
]

api_key = APIKeyHeader(name="X-API-Key")

def usuario_actual(clave: str = Depends(api_key)):
    usuario = usuarios.get(clave)
    if not usuario:
        raise HTTPException(401, "Credenciales invalidas")
    return usuario

class NuevoPedido(BaseModel):
    articulo: str = Field(min_length=1, max_length=100)
    cantidad: int = Field(gt=0, le=100)
    model_config = ConfigDict(extra="forbid")

class ActualizarPerfil(BaseModel):
    nombre: str = Field(min_length=1, max_length=100)
    model_config = ConfigDict(extra="forbid")

@app.get("/api/orders/{id}")
def consultar_pedido(id: int, usuario=Depends(usuario_actual)):
    pedido = pedidos.get(id)
    if not pedido:
        raise HTTPException(404, "Pedido no encontrado")
    if pedido["owner_id"] != usuario["id"] and usuario["rol"] != "admin":
        raise HTTPException(403, "Acceso denegado")
    return pedido

@app.get("/api/admin/audit")
def consultar_auditoria(usuario=Depends(usuario_actual)):
    if usuario["rol"] != "admin":
        raise HTTPException(403, "Funcion exclusiva del administrador")
    return auditoria

@app.patch("/api/profile")
def actualizar_perfil(datos: ActualizarPerfil, usuario=Depends(usuario_actual)):
    perfiles[usuario["id"]]["nombre"] = datos.nombre
    return {"mensaje": "Perfil actualizado", "perfil": perfiles[usuario["id"]]}

@app.post("/api/orders", status_code=201)
def crear_pedido(datos: NuevoPedido, usuario=Depends(usuario_actual)):
    nuevo_id = max(pedidos.keys(), default=0) + 1
    pedido = {
        "id": nuevo_id,
        "owner_id": usuario["id"],
        "articulo": datos.articulo,
        "cantidad": datos.cantidad
    }
    pedidos[nuevo_id] = pedido
    return pedido

import strawberry
from strawberry.fastapi import GraphQLRouter

@strawberry.type
class PedidoGraphQL:
    id: int
    articulo: str
    cantidad: int

@strawberry.type
class UsuarioGraphQL:
    nombre: str
    pedidos: list[PedidoGraphQL]

@strawberry.type
class Query:
    @strawberry.field
    def usuario(self) -> UsuarioGraphQL:
        return UsuarioGraphQL(
            nombre="Usuario A",
            pedidos=[
                PedidoGraphQL(
                    id=1,
                    articulo="Computadora",
                    cantidad=1
                )
            ]
        )

schema = strawberry.Schema(query=Query)
graphql_app = GraphQLRouter(schema)

app.include_router(graphql_app, prefix="/graphql")


@app.get("/api/profile", summary="Consultar Perfil")
def consultar_perfil(usuario=Depends(usuario_actual)):
    perfil = perfiles.get(usuario["id"])

    if perfil is None:
        raise HTTPException(
            status_code=404,
            detail="Perfil no encontrado"
        )

    return {
        "nombre": perfil["nombre"]
    }
