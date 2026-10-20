import tempfile
import unittest
import os
import secrets
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.database import Base
from app import models, financial_models, rbac_models  # noqa: F401 - registra tablas
from app.models import Company, CompanyUser, User
from app.rbac import seed_rbac
from app.rbac_models import PermissionModel, RoleModel, RolePermissionModel
from app.schema import schema
from app.security import create_access_token
import app.schema as schema_module


class RolePermissionsTest(unittest.TestCase):
    def setUp(self):
        self.secret_patch = patch.dict(os.environ, {"JWT_SECRET": secrets.token_hex(32)})
        self.secret_patch.start()
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary.name) / "permisos.sqlite"
        self.engine = create_engine(f"sqlite:///{self.database_path}")
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, autoflush=False)
        with self.session_factory() as db:
            db.add(Company(name="Empresa de prueba"))
            db.add(User(name="Ana", email="ana@example.test", password_hash="valor-ficticio"))
            db.flush()
            db.add(CompanyUser(company_id=1, user_id=1, is_admin=True))
            db.commit()
            seed_rbac(db)
            self.actor = str(db.scalar(select(CompanyUser.id)))
            self.token = create_access_token(int(self.actor), 1)
            self.role = str(db.scalar(select(RoleModel.id).where(RoleModel.code == "CAPTURISTA")))
            self.permissions = {p.code: str(p.id) for p in db.scalars(select(PermissionModel)).all()}
        self.original_sessions = schema_module.SessionLocal
        schema_module.SessionLocal = self.session_factory

    def tearDown(self):
        self.secret_patch.stop()
        schema_module.SessionLocal = self.original_sessions
        self.engine.dispose()
        self.temporary.cleanup()

    def execute(self, operation, permission_codes):
        return schema.execute_sync(operation, variable_values={
            "input": {"roleId": self.role,
                      "permissionIds": [self.permissions[code] for code in permission_codes]},
        }, context_value={"request": SimpleNamespace(headers={"authorization": f"Bearer {self.token}"})})

    def active_codes(self):
        with self.session_factory() as db:
            return {p.code for p in db.scalars(
                select(PermissionModel).join(RolePermissionModel).where(
                    RolePermissionModel.role_id == int(self.role),
                    RolePermissionModel.is_active.is_(True)
                )).all()}

    def test_preview_apply_idempotence_empty_and_restart(self):
        initial = sorted(["accounts.read", "concepts.read", "transactions.read", "transactions.write"])
        requested = initial + ["accounts.write"]
        preview = """query P($input: SetRolePermissionsInput!) {
          previewRolePermissions(input: $input) {
            toActivate { code } finalCount
          }
        }"""
        apply = """mutation A($input: SetRolePermissionsInput!) {
          setRolePermissions(input: $input) {
            activated { code } deactivated { code } finalCount changed
          }
        }"""
        result = self.execute(preview, requested)
        self.assertIsNone(result.errors)
        self.assertEqual(result.data["previewRolePermissions"]["toActivate"], [{"code": "accounts.write"}])
        self.assertEqual(self.active_codes(), set(initial))
        first = self.execute(apply, requested)
        self.assertIsNone(first.errors)
        self.assertTrue(first.data["setRolePermissions"]["changed"])
        second = self.execute(apply, requested)
        self.assertIsNone(second.errors)
        self.assertFalse(second.data["setRolePermissions"]["changed"])
        self.assertEqual(second.data["setRolePermissions"]["activated"], [])
        self.assertEqual(self.active_codes(), set(requested))
        self.assertIsNone(self.execute(apply, []).errors)
        with self.session_factory() as db:
            seed_rbac(db)
        self.assertEqual(self.active_codes(), set())
        self.assertIsNone(self.execute(apply, initial).errors)
        self.assertEqual(self.active_codes(), set(initial))

    def test_e07_rollback_after_flush(self):
        operation = """mutation A($input: SetRolePermissionsInput!) {
          setRolePermissions(input: $input) { changed }
        }"""
        requested = ["accounts.read", "accounts.write"]
        before = self.active_codes()
        original_flush = Session.flush

        def fail_after_flush(session, *args, **kwargs):
            original_flush(session, *args, **kwargs)
            raise RuntimeError("Fallo controlado después de flush")

        with patch.object(Session, "flush", fail_after_flush):
            result = self.execute(operation, requested)
        self.assertIsNotNone(result.errors)
        self.assertIn("Fallo controlado", str(result.errors[0]))
        self.assertEqual(self.active_codes(), before)


if __name__ == "__main__":
    unittest.main()
