import os
import secrets
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jwt
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import financial_models, models, rbac_models  # noqa: F401
from app.database import Base
from app.financial_models import Account, AccountConcept, Concept, Transaction
from app.models import Company, CompanyUser, User
from app.rbac import assign_role_internal, seed_rbac
from app.rbac_models import RoleModel
from app.schema import schema
from app.security import create_access_token, hash_password
import app.schema as schema_module


class AccessByRoleTest(unittest.TestCase):
    def setUp(self):
        self.secret = secrets.token_hex(32)
        self.secret_patch = patch.dict(os.environ, {"JWT_SECRET": self.secret})
        self.secret_patch.start()
        self.temporary = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.temporary.name) / 'access.sqlite'}")
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, autoflush=False)
        self.original_sessions = schema_module.SessionLocal
        schema_module.SessionLocal = self.sessions
        with self.sessions() as db:
            company = Company(name="Empresa de prueba")
            other = Company(name="Otra empresa")
            db.add_all([company, other])
            db.flush()
            self.company_id, self.other_company_id = company.id, other.id
            for name, email, admin, company_id in (
                ("Ana", "ana@example.com", True, company.id),
                ("María", "maria@example.com", False, company.id),
                ("Luis", "luis@example.com", False, company.id),
                ("Pedro", "pedro@example.com", False, company.id),
                ("Orion", "orion@example.com", True, other.id),
            ):
                user = User(name=name, email=email, password_hash=hash_password("secreto-pruebas"))
                db.add(user)
                db.flush()
                member = CompanyUser(company_id=company_id, user_id=user.id, is_admin=admin)
                db.add(member)
                db.flush()
                setattr(self, name.lower().replace("í", "i"), member.id)
            db.commit()
            seed_rbac(db)
            roles = {r.code: r for r in db.scalars(select(RoleModel)).all()}
            for member_id, code in ((self.maria, "CAPTURISTA"), (self.luis, "CONTADOR")):
                assign_role_internal(db, db.get(CompanyUser, member_id), roles[code])
            account = Account(company_id=company.id, account_type="CASH", name="Caja")
            other_account = Account(company_id=other.id, account_type="CASH", name="Caja de otra empresa")
            concept = Concept(company_id=company.id, concept_type="INCOME", name="Ingreso")
            db.add_all([account, other_account, concept])
            db.flush()
            db.add(AccountConcept(account_id=account.id, concept_id=concept.id))
            db.commit()
            self.account_id, self.concept_id = account.id, concept.id
            self.other_account_id = other_account.id
            self.capturista_role_id = roles["CAPTURISTA"].id
        self.tokens = {name: create_access_token(getattr(self, name),
                        self.other_company_id if name == "orion" else self.company_id)
                       for name in ("ana", "maria", "luis", "pedro", "orion")}

    def tearDown(self):
        schema_module.SessionLocal = self.original_sessions
        self.engine.dispose()
        self.temporary.cleanup()
        self.secret_patch.stop()

    def execute(self, query, token=None):
        headers = {"authorization": f"Bearer {token}"} if token else {}
        return schema.execute_sync(query, context_value={"request": SimpleNamespace(headers=headers)})

    def count(self, model):
        with self.sessions() as db:
            return db.scalar(select(func.count()).select_from(model))

    def transaction(self, label):
        return f'''mutation {{ createTransaction(input: {{accountId: "{self.account_id}", conceptId: "{self.concept_id}", transactionType: INCOME, amount: "10.00", shortDescription: "{label}"}}) {{ id }} }}'''

    def account(self, label, company_id=None):
        company_id = company_id or self.company_id
        return f'''mutation {{ createAccount(input: {{companyId: "{company_id}", accountType: CASH, name: "{label}"}}) {{ id }} }}'''

    def test_login_claims_and_rejected_password(self):
        good = self.execute('mutation { login(input: {email: "maria@example.com", password: "secreto-pruebas"}) { token tokenType user { name } } }')
        self.assertIsNone(good.errors)
        payload = good.data["login"]
        self.assertEqual(payload["tokenType"], "bearer")
        claims = jwt.decode(payload["token"], self.secret, algorithms=["HS256"])
        self.assertEqual(set(claims), {"companyUserId", "companyId", "exp"})
        self.assertEqual(claims["companyUserId"], self.maria)
        self.assertEqual(claims["companyId"], self.company_id)
        self.assertTrue(29 * 60 <= claims["exp"] - datetime.now(timezone.utc).timestamp() <= 30 * 60)
        bad = self.execute('mutation { login(input: {email: "maria@example.com", password: "incorrecta"}) { token } }')
        self.assertTrue(bad.errors)
        self.assertIsNone(bad.data)

    def test_login_selects_only_own_active_membership(self):
        with self.sessions() as db:
            maria = db.get(CompanyUser, self.maria)
            second = CompanyUser(company_id=self.other_company_id, user_id=maria.user_id)
            db.add(second)
            db.commit()
            second_id = second.id
        without_selection = self.execute('mutation { login(input: {email: "maria@example.com", password: "secreto-pruebas"}) { token } }')
        self.assertTrue(without_selection.errors)
        for member_id, company_id in ((self.maria, self.company_id), (second_id, self.other_company_id)):
            result = self.execute(f'mutation {{ login(input: {{email: "maria@example.com", password: "secreto-pruebas", companyUserId: "{member_id}"}}) {{ token }} }}')
            self.assertIsNone(result.errors)
            claims = jwt.decode(result.data["login"]["token"], self.secret, algorithms=["HS256"])
            self.assertEqual((claims["companyUserId"], claims["companyId"]), (member_id, company_id))
        other_person = self.execute(f'mutation {{ login(input: {{email: "maria@example.com", password: "secreto-pruebas", companyUserId: "{self.ana}"}}) {{ token }} }}')
        self.assertTrue(other_person.errors)

    def test_cases_1_to_9(self):
        before_accounts = self.count(Account)
        no_token = self.execute(self.account("sin-token"))
        self.assertTrue(no_token.errors)
        self.assertEqual(self.count(Account), before_accounts)

        before_transactions = self.count(Transaction)
        self.assertIsNone(self.execute(self.transaction("maria-permitido"), self.tokens["maria"]).errors)
        self.assertEqual(self.count(Transaction), before_transactions + 1)

        denied_maria = self.execute(self.account("maria-rechazado"), self.tokens["maria"])
        self.assertTrue(denied_maria.errors)
        self.assertEqual(self.count(Account), before_accounts)

        self.assertIsNone(self.execute(self.account("luis-permitido"), self.tokens["luis"]).errors)
        self.assertEqual(self.count(Account), before_accounts + 1)

        denied_pedro = self.execute(self.transaction("pedro-rechazado"), self.tokens["pedro"])
        self.assertTrue(denied_pedro.errors)
        self.assertEqual(self.count(Transaction), before_transactions + 1)

        promoted = self.execute(f'mutation {{ assignRole(input: {{companyUserId: "{self.pedro}", roleId: "{self.capturista_role_id}"}}) {{ role {{ code }} }} }}', self.tokens["ana"])
        self.assertIsNone(promoted.errors)
        self.assertEqual(promoted.data["assignRole"]["role"]["code"], "CAPTURISTA")
        self.assertIsNone(self.execute(self.transaction("pedro-permitido"), self.tokens["pedro"]).errors)
        self.assertEqual(self.count(Transaction), before_transactions + 2)

        own_accounts = self.execute('query { accounts { id companyId } }', self.tokens["orion"])
        self.assertIsNone(own_accounts.errors)
        self.assertEqual(own_accounts.data["accounts"], [{"id": str(self.other_account_id), "companyId": str(self.other_company_id)}])
        cannot_choose_company = self.execute(f'query {{ accounts(companyId: "{self.company_id}") {{ id }} }}', self.tokens["orion"])
        self.assertTrue(cannot_choose_company.errors)
        other_company = self.execute(self.account("otra-empresa", self.company_id), self.tokens["orion"])
        self.assertTrue(other_company.errors)
        self.assertEqual(self.count(Account), before_accounts + 1)

        altered = self.tokens["luis"][:-1] + ("a" if self.tokens["luis"][-1] != "a" else "b")
        expired = jwt.encode({"companyUserId": self.luis, "companyId": self.company_id,
                              "exp": datetime.now(timezone.utc) - timedelta(seconds=1)},
                             self.secret, algorithm="HS256")
        for token in (altered, expired):
            self.assertTrue(self.execute(self.account("token-invalido"), token).errors)
            self.assertEqual(self.count(Account), before_accounts + 1)
        self.assertTrue(self.execute(self.account("id-ajeno").replace('input:', f'actorCompanyUserId: "{self.ana}", input:'), self.tokens["maria"]).errors)


if __name__ == "__main__":
    unittest.main()
