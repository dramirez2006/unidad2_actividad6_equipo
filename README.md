# Unidad II · Actividad 6 · Control de acceso según el rol

Equipo: Angel, Juan Jose, Orion, Josue y Diego.

## Ejecutar

En `ingresos/`, instalar `requirements.txt`, iniciar MySQL con `docker compose up -d` y crear `.env` desde `.env.example`. Generar `JWT_SECRET` localmente con `python -c "import secrets; print(secrets.token_hex(32))"` y colocarlo solo en `.env`. Ejecutar `uvicorn app.main:app` y abrir `/graphql`.

`login` recibe correo y contraseña. Si la persona tiene una sola membresía activa, no necesita indicar su ID. Si tiene más de una, añade `companyUserId` al `input` de `login` para seleccionar una membresía propia. El servidor obtiene `companyId` de esa fila. La respuesta contiene `tokenType: "bearer"`, el token y los datos mínimos del usuario. El token dura 30 minutos.

Para las operaciones protegidas, enviar `Authorization: Bearer TOKEN` en el encabezado HTTP de GraphiQL. Las operaciones ya no admiten `actorCompanyUserId`. `accounts`, `concepts` y `companyUsers` toman la empresa del token.

## Verificación

Desde `ingresos/`: `python -m unittest discover -s tests -v`. Las pruebas de acceso usan una base SQLite temporal. La prueba de rollback en MySQL se activa con `RUN_MYSQL_TESTS=1 python -m unittest tests/test_e07_mysql.py -v`.

`evidencias/` contiene los logins y los casos 1 a 9 capturados contra `/graphql`, los datos legibles del JWT y las consultas SQL de comprobación. Se usó una copia aislada de la base de las actividades 4 y 5. No se guardan contraseñas reales, `JWT_SECRET`, tokens vigentes ni ambientes virtuales en esta entrega.
