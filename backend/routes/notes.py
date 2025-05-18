# -----------------------------------
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app import crud, dependencies
from schemas import user as schemas
from models import user as models

router = APIRouter()


@router.get("/notes", response_model=list[schemas.Note])
def read_notes(
    current_user: models.User = Depends(dependencies.get_current_user),
    db: Session = Depends(dependencies.get_db),
):
    return crud.get_notes(db, user_id=current_user.id)


@router.post("/notes", response_model=schemas.Note)
def create_note(
    note: schemas.NoteCreate,
    current_user: models.User = Depends(dependencies.get_current_user),
    db: Session = Depends(dependencies.get_db),
):
    return crud.create_note(db, note, user_id=current_user.id)


@router.put("/notes/{note_id}", response_model=schemas.Note)
def update_note(
    note_id: int,
    note: schemas.NoteCreate,
    current_user: models.User = Depends(dependencies.get_current_user),
    db: Session = Depends(dependencies.get_db),
):
    return crud.update_note(db, note_id, content=note.content)


@router.delete("/notes/{note_id}")
def delete_note(
    note_id: int,
    current_user: models.User = Depends(dependencies.get_current_user),
    db: Session = Depends(dependencies.get_db),
):
    crud.delete_note(db, note_id)
    return {"detail": "Note deleted"}
