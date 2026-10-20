import os
import secrets
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import CompanyUser
from app.rbac_models import CompanyUserRoleModel, PermissionModel, RoleModel, RolePermissionModel
from app.schema import schema
from app.security import create_access_token


@unittest.skipUnless(os.getenv("RUN_MYSQL_TESTS") == "1", "Requiere MySQL local de laboratorio")
class RollbackMySQLTest(unittest.TestCase):
    def state(self, role_id):
        with SessionLocal() as db:
            return [(row.id, row.permission_id, row.is_active) for row in db.scalars(
                select(RolePermissionModel).where(RolePermissionModel.role_id == role_id)
                .order_by(RolePermissionModel.id)
            ).all()]

    def test_e07_rollback_desde_sesion_nueva(self):
        with SessionLocal() as db:
            role_id = db.scalar(select(RoleModel.id).where(RoleModel.code == "CAPTURISTA"))
            permission_id = db.scalar(select(PermissionModel.id).where(PermissionModel.code == "accounts.write"))
            actor_id = db.scalar(select(CompanyUser.id).join(CompanyUserRoleModel).join(RoleModel).where(
                RoleModel.code == "ADMINISTRADOR", CompanyUserRoleModel.is_active.is_(True),
                CompanyUser.is_active.is_(True)
            ).limit(1))
        self.assertIsNotNone(actor_id)
        before = self.state(role_id)
        active = [permission_id for _, permission_id, enabled in before if enabled]
        desired = [str(value) for value in active if value != permission_id]
        if permission_id not in active:
            desired.append(str(permission_id))

        original_flush = Session.flush

        def fail_after_flush(session, *args, **kwargs):
            original_flush(session, *args, **kwargs)
            raise RuntimeError("Fallo controlado después de flush y antes de commit")

        operation = """mutation E07($input: SetRolePermissionsInput!) {
            setRolePermissions(input: $input) { changed }
        }"""
        with patch.dict(os.environ, {"JWT_SECRET": secrets.token_hex(32)}):
            with SessionLocal() as db:
                actor = db.get(CompanyUser, actor_id)
                token = create_access_token(actor.id, actor.company_id)
            with patch.object(Session, "flush", fail_after_flush):
                result = schema.execute_sync(operation, variable_values={
                    "input": {"roleId": str(role_id), "permissionIds": desired},
                }, context_value={"request": SimpleNamespace(headers={"authorization": f"Bearer {token}"})})
        self.assertIsNotNone(result.errors)
        self.assertIn("Fallo controlado", str(result.errors[0]))
        after = self.state(role_id)
        self.assertEqual(after, before)
        print(f"E07 MySQL: error tras flush; antes={before}; sesion_nueva={after}")


if __name__ == "__main__":
    unittest.main()
