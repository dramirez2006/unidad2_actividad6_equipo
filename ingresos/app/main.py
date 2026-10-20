from contextlib import asynccontextmanager

from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter

from app.database import Base, engine
from app.schema import schema
from app.database import SessionLocal
from app.rbac import seed_rbac


@asynccontextmanager
async def lifespan(app: FastAPI):

    Base.metadata.create_all(
        bind=engine
    )

    with SessionLocal() as db:
        seed_rbac(db)

    yield


app = FastAPI(
    title="Unidad II - Actividad 6 - Control de acceso según el rol",

    description=(
        "Gestión de empresas, usuarios, cuentas, conceptos "
        "y movimientos financieros mediante GraphQL"
    ),

    lifespan=lifespan,
)


graphql_app = GraphQLRouter(
    schema,
    graphql_ide="graphiql"
)


app.include_router(
    graphql_app,
    prefix="/graphql"
)


@app.get("/")
def root():
    return {
        "message": "Actividad 6 - Control de acceso según el rol",
        "graphql": "/graphql"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
