# Evidencias

`graphiql/` contiene las capturas directas de login y de los casos 1 a 9. Las consultas se ejecutaron en el orden de la actividad contra `/graphql`, con las personas y los roles de las actividades 4 y 5. El caso 7 usó el mismo token de Pedro que el caso 5. `caso_08_propia.png` muestra las cuentas que sí puede leer la empresa 2; `caso_09a.png` y `caso_09b.png` comprueban las dos formas de token inválido.

Los textos de las capturas se muestran en negro. El token, la firma y la contraseña temporal se ocultaron en GraphiQL después de ejecutar cada petición y antes de capturar la pantalla. El encabezado real sí se envió al servidor.

`datos_legibles_jwt.txt` contiene únicamente companyUserId, companyId y exp del login correcto. `comprobaciones_mysql.txt` muestra las consultas ejecutadas en MySQL y cero filas para las escrituras rechazadas.

Las pruebas se realizaron sobre `actividad6_graphiql`, copia aislada de la base de las actividades anteriores. La base original `actividad4_db` no se modificó.
