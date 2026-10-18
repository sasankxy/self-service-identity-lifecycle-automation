"""Create (or promote) the first Super Administrator. Public signup can never create admins.

    python -m scripts.create_admin --email you@corp.com --name "Your Name"
Password is read from the BOOTSTRAP_ADMIN_PASSWORD env var or prompted (never passed as an argument).
"""
import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.core.security import hash_password, password_problems
from app.models.auth import User
from app.models.governance import AuditLog
from app.services import accounts


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--name", required=True)
    args = ap.parse_args()
    email = args.email.strip().lower()
    s = get_settings()
    password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD") or getpass.getpass("Password: ")
    probs = password_problems(password, email, args.name, s.password_min_length)
    if probs:
        print("Weak password; needs: " + ", ".join(probs))
        return 1
    engine = create_async_engine(s.database_url)
    async with async_sessionmaker(engine, expire_on_commit=False)() as db:
        await accounts.ensure_reference_data(db)
        user = await accounts.get_user_by_email(db, email)
        if user is None:
            user = User(email=email, full_name=args.name, password_hash=await hash_password(password), status="active")
            db.add(user)
            await db.flush()
            created = True
        else:
            user.status, created = "active", False   # existing account is promoted; password unchanged
        await accounts.set_roles(db, user.id, ["super_admin"], None)
        db.add(AuditLog(actor_label="cli:create_admin", action="user.bootstrap_admin", target_type="user",
                        target_id=str(user.id), severity="high", details={"email": email, "created": created}))
        await db.commit()
    await engine.dispose()
    print(f"{'Created' if created else 'Promoted'} super administrator {email}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
