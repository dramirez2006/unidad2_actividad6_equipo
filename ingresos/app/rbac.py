from sqlalchemy import select
from sqlalchemy.orm import Session
from graphql import GraphQLError

from app.models import Company, CompanyUser, User
from app.rbac_models import CompanyUserRoleModel, PermissionModel, RoleModel, RolePermissionModel


ROLE_NAMES = {
    "ADMINISTRADOR": "Administrador",
    "CONTADOR": "Contador",
    "CAPTURISTA": "Capturista",
    "CONSULTA": "Consulta",
}

PERMISSION_NAMES = {
    "company.users.read": "Consultar membresías",
    "company.users.write": "Administrar membresías",
    "accounts.read": "Consultar cuentas",
    "accounts.write": "Crear cuentas",
    "concepts.read": "Consultar conceptos",
    "concepts.write": "Administrar conceptos",
    "transactions.read": "Consultar movimientos",
    "transactions.write": "Registrar movimientos",
    "roles.read": "Consultar roles y permisos",
    "roles.write": "Administrar roles y permisos",
}

PERMISSION_MATRIX = {
    "ADMINISTRADOR": list(PERMISSION_NAMES),
    "CONTADOR": [
        "company.users.read", "accounts.read", "accounts.write", "concepts.read",
        "concepts.write", "transactions.read", "transactions.write", "roles.read",
    ],
    "CAPTURISTA": ["accounts.read", "concepts.read", "transactions.read", "transactions.write"],
    "CONSULTA": ["company.users.read", "accounts.read", "concepts.read", "transactions.read"],
}


def seed_rbac(db: Session) -> None:
    for code, name in ROLE_NAMES.items():
        if db.scalar(select(RoleModel).where(RoleModel.code == code)) is None:
            db.add(RoleModel(code=code, name=name, description=name))
    for code, name in PERMISSION_NAMES.items():
        if db.scalar(select(PermissionModel).where(PermissionModel.code == code)) is None:
            db.add(PermissionModel(code=code, name=name, description=name))
    db.flush()
    roles = {r.code: r for r in db.scalars(select(RoleModel)).all()}
    permissions = {p.code: p for p in db.scalars(select(PermissionModel)).all()}
    for role_code, codes in PERMISSION_MATRIX.items():
        role = roles[role_code]
        found = db.scalar(select(RolePermissionModel.id).where(RolePermissionModel.role_id == role.id).limit(1))
        if found is not None:
            continue
        for code in codes:
            entry = db.scalar(select(RolePermissionModel).where(RolePermissionModel.role_id == role.id, RolePermissionModel.permission_id == permissions[code].id))
            if entry is None:
                db.add(RolePermissionModel(role_id=role.id, permission_id=permissions[code].id))
            else:
                entry.is_active = True
    db.flush()
    memberships = db.scalars(select(CompanyUser).where(CompanyUser.is_active.is_(True))).all()
    for membership in memberships:
        active = db.scalar(select(CompanyUserRoleModel.id).where(CompanyUserRoleModel.company_user_id == membership.id, CompanyUserRoleModel.is_active.is_(True)))
        if active is None:
            code = "ADMINISTRADOR" if membership.is_admin else "CONSULTA"
            assign_role_internal(db, membership, roles[code])
    db.commit()


def assign_role_internal(db: Session, membership: CompanyUser, role: RoleModel) -> CompanyUserRoleModel:
    if not membership.is_active or not membership.company.is_active or not membership.user.is_active:
        raise GraphQLError("La membresía, empresa o usuario está inactivo.")
    if not role.is_active:
        raise GraphQLError("El rol está inactivo.")
    if membership.is_admin and role.code != "ADMINISTRADOR":
        raise GraphQLError("El administrador principal debe mantener el rol ADMINISTRADOR.")
    if not membership.is_admin and role.code == "ADMINISTRADOR":
        raise GraphQLError("El rol ADMINISTRADOR está reservado al administrador principal.")
    active = db.scalars(select(CompanyUserRoleModel).where(CompanyUserRoleModel.company_user_id == membership.id, CompanyUserRoleModel.is_active.is_(True))).all()
    if len(active) == 1 and active[0].role_id == role.id:
        return active[0]
    for entry in active:
        entry.is_active = False
    existing = db.scalar(select(CompanyUserRoleModel).where(CompanyUserRoleModel.company_user_id == membership.id, CompanyUserRoleModel.role_id == role.id))
    if existing is None:
        existing = CompanyUserRoleModel(company_user_id=membership.id, role_id=role.id)
        db.add(existing)
    else:
        existing.is_active = True
    db.flush()
    return existing


def exigir_permiso(db: Session, company_user_id: int, codigo: str, company_id: int | None = None) -> CompanyUser:
    member = db.get(CompanyUser, company_user_id)
    if member is None or not member.is_active or not member.user.is_active or not member.company.is_active:
        raise GraphQLError("La membresía no existe o está inactiva.")
    if company_id is not None and member.company_id != company_id:
        raise GraphQLError("Los datos no pertenecen a la empresa de esta membresía.")
    assignment = db.scalar(select(CompanyUserRoleModel).join(RoleModel).where(
        CompanyUserRoleModel.company_user_id == company_user_id,
        CompanyUserRoleModel.is_active.is_(True), RoleModel.is_active.is_(True)))
    if assignment is None:
        raise GraphQLError("La membresía no tiene un rol activo.")
    allowed = db.scalar(select(RolePermissionModel.id).join(PermissionModel).where(
        RolePermissionModel.role_id == assignment.role_id,
        RolePermissionModel.is_active.is_(True),
        PermissionModel.code == codigo, PermissionModel.is_active.is_(True)))
    if allowed is None:
        raise GraphQLError(f"El rol no tiene el permiso {codigo}.")
    return member
