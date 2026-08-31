from pathlib import Path

from memsentry.models.case import CaseCreate
from memsentry.storage.database import Database
from memsentry.storage.repositories.case_repository import CaseRepository


database = Database(
    Path("runtime/database/memsentry.db")
)

database.initialize()

repository = CaseRepository(database)

case = repository.create(
    CaseCreate(
        case_number="CASE-2026-001",
        name="Test Memory Investigation",
        description="Testing case database functionality.",
    )
)

print("Case created:")
print(case)

print()
print("ID:", case.id)
print("Number:", case.case_number)
print("Name:", case.name)
print("Status:", case.status)
print("Created:", case.created_at)