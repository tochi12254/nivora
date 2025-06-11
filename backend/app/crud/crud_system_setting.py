from typing import Any, Optional
import json # For serializing to JSON string if the DB driver requires it for JSON type

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.dialects.postgresql import insert as pg_insert # For PostgreSQL UPSERT
from sqlalchemy.dialects.sqlite import insert as sqlite_insert # For SQLite UPSERT

from ..models.system_setting import SystemSetting
# from backend.app.schemas.system_setting import SettingCreate # Not directly used for upsert by value

async def get_setting(db: AsyncSession, key: str) -> Optional[SystemSetting]:
    """
    Retrieve a setting by its key.
    """
    result = await db.execute(select(SystemSetting).filter(SystemSetting.key == key))
    return result.scalar_one_or_none()

async def upsert_setting(db: AsyncSession, key: str, value: Any) -> SystemSetting:
    """
    Create or update a setting.
    The 'value' is a Python object (e.g., str, list, dict, int)
    and will be stored as JSON in the database.
    """
    # Attempt to get the existing setting
    existing_setting = await get_setting(db, key)

    if existing_setting:
        # Update existing setting
        existing_setting.value = value # SQLAlchemy's JSON type handles Python dicts/lists
        db.add(existing_setting)
        await db.commit()
        await db.refresh(existing_setting)
        return existing_setting
    else:
        # Create new setting
        # The 'value' should be directly assignable if the column type is JSON/JSONB
        # and the SQLAlchemy dialect handles serialization.
        new_setting = SystemSetting(key=key, value=value)
        db.add(new_setting)
        await db.commit()
        await db.refresh(new_setting)
        return new_setting

# Alternative upsert using database-specific ON CONFLICT clauses (more atomic)
# This is generally preferred if your database supports it well with SQLAlchemy.
async def upsert_setting_atomic(db: AsyncSession, key: str, value: Any) -> SystemSetting:
    """
    Create or update a setting using an atomic UPSERT operation.
    The 'value' is a Python object and will be stored as JSON.
    """
    # Determine dialect for appropriate insert statement
    dialect_name = db.bind.dialect.name

    if dialect_name == "postgresql":
        stmt = pg_insert(SystemSetting).values(key=key, value=value)
        stmt = stmt.on_conflict_do_update(
            index_elements=[SystemSetting.key],
            set_=dict(value=value)
        )
    elif dialect_name == "sqlite":
        stmt = sqlite_insert(SystemSetting).values(key=key, value=value)
        stmt = stmt.on_conflict_do_update(
            index_elements=[SystemSetting.key],
            set_=dict(value=value)
        )
    else:
        # Fallback to get-then-update for other dialects or if specific upsert is complex
        # This is the same as the non-atomic version above.
        # For production, you might want to raise an error or log if an expected dialect isn't matched.
        return await upsert_setting(db, key, value) # Calling the non-atomic version

    await db.execute(stmt)
    await db.commit()
    
    # After upsert, we need to fetch the object to return it, as execute() on insert doesn't return the model instance directly
    # in the same way as add() -> refresh().
    updated_setting = await get_setting(db, key)
    if updated_setting is None:
        # This should ideally not happen if the upsert was successful
        raise Exception(f"Setting '{key}' not found after upsert operation.")
    return updated_setting

# For this implementation, we'll export the simpler, non-atomic upsert_setting first.
# If issues arise or atomicity is critical, upsert_setting_atomic can be used/refined.
# The main difference is that the non-atomic one involves two separate DB operations (SELECT then INSERT/UPDATE)
# whereas the atomic one is a single operation.

# For the subtask, upsert_setting (non-atomic) is sufficient unless specified otherwise.
# Let's stick to the simpler `upsert_setting` for now as it's more universally compatible
# without needing to handle dialect specifics as explicitly in the calling code,
# though the atomic version is generally better practice for supported DBs.
# The task asks for `upsert_setting(db: AsyncSession, key: str, value: Any) -> SystemSetting`,
# so I will provide the first version implemented.
