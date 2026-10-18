import asyncio
from app.core.config import get_settings
from sqlalchemy.ext.asyncio import create_async_engine

async def main():
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    try:
        async with engine.connect() as conn:
            result = await conn.exec_driver_sql(
                "SELECT current_user, current_database()"
            )
            print("Connection successful:", result.fetchone())
    finally:
        await engine.dispose()

asyncio.run(main())
