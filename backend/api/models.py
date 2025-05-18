from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from typing import List, Optional, Dict
import os
from pathlib import Path
import joblib
import pandas as pd
import numpy as np
import logging

from app.database import get_db
from models.model import Model as DBModel
from schemas.model import (
    ModelBase,
    ModelCreate,
    ModelUpdate,
    ModelResponse,
    ModelPrediction,
    ModelType,
    ModelStatus,
)
from app.utils.security import JWTBearer, role_required
from app.utils.monitoring import track_function_metrics

router = APIRouter(tags=["Models"])
logger = logging.getLogger(__name__)

MODELS_DIR = Path("app/data/models")
MODELS_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/models", response_model=ModelResponse, status_code=201)
@role_required(["admin", "data_scientist"])
@track_function_metrics("model_create")
async def create_model(
    model: ModelCreate,
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(JWTBearer()),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new machine learning model entry and initiate training

    Args:
        model: Model creation data
        background_tasks: FastAPI background tasks handler
        current_user: Authenticated user
        db: Async database session

    Returns:
        ModelResponse: Created model details
    """
    try:
        # Check if model version already exists
        result = await db.execute(
            select(DBModel)
            .where(DBModel.name == model.name)
            .where(DBModel.version == model.version)
        )
        existing_model = result.scalars().first()

        if existing_model:
            raise HTTPException(
                status_code=400,
                detail=f"Model {model.name} version {model.version} already exists",
            )

        # Create new model record
        db_model = DBModel(
            name=model.name,
            type=model.type,
            version=model.version,
            description=model.description,
            parameters=model.parameters,
            status=ModelStatus.TRAINING,
            created_by=current_user.get("sub"),
        )

        db.add(db_model)
        await db.commit()
        await db.refresh(db_model)

        # Start background training task
        background_tasks.add_task(
            train_model_task,
            db_model.id,
            model.training_data_path,
            model.parameters,
            current_user.get("sub"),
        )

        return db_model

    except Exception as e:
        logger.error(f"Failed to create model: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to create model")


async def train_model_task(
    model_id: int, training_data_path: str, parameters: dict, user_id: str
):
    """
    Background task for model training

    Args:
        model_id: ID of model to train
        training_data_path: Path to training data
        parameters: Training parameters
        user_id: User ID who initiated training
    """
    async with AsyncSessionLocal() as db:
        try:
            # Get model record
            result = await db.execute(select(DBModel).where(DBModel.id == model_id))
            model = result.scalars().first()

            if not model:
                logger.error(f"Model {model_id} not found for training")
                return

            # Update model status
            model.status = ModelStatus.TRAINING
            model.updated_by = user_id
            await db.commit()

            # TODO: Implement actual model training
            logger.info(f"Starting training for model {model_id}")

            # Simulate training process
            await asyncio.sleep(10)  # Simulate training time

            # Save trained model
            model_path = MODELS_DIR / str(model_id) / f"model_v{model.version}.joblib"
            model_path.parent.mkdir(exist_ok=True)

            # Create a dummy model for demonstration
            from sklearn.ensemble import RandomForestClassifier

            dummy_model = RandomForestClassifier(**parameters)
            joblib.dump(dummy_model, model_path)

            # Update model status
            model.status = ModelStatus.ACTIVE
            model.accuracy = 0.95  # Simulated accuracy
            model.last_trained = datetime.utcnow()
            await db.commit()

            logger.info(f"Completed training for model {model_id}")

        except Exception as e:
            logger.error(f"Model training failed: {str(e)}", exc_info=True)
            if model:
                model.status = ModelStatus.ERROR
                await db.commit()


@router.get("/models", response_model=List[ModelResponse])
@role_required(["admin", "data_scientist", "security_analyst"])
@track_function_metrics("model_list")
async def list_models(
    skip: int = 0,
    limit: int = 100,
    type: Optional[ModelType] = None,
    status: Optional[ModelStatus] = None,
    current_user: Dict = Depends(JWTBearer()),
    db: AsyncSession = Depends(get_db),
):
    """
    List all available models with optional filtering

    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        type: Filter by model type
        status: Filter by model status
        current_user: Authenticated user
        db: Async database session

    Returns:
        List[ModelResponse]: List of models
    """
    try:
        query = select(DBModel)

        if type:
            query = query.where(DBModel.type == type)
        if status:
            query = query.where(DBModel.status == status)

        result = await db.execute(query.offset(skip).limit(limit))
        models = result.scalars().all()

        return models

    except Exception as e:
        logger.error(f"Failed to list models: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list models")


@router.get("/models/{model_id}", response_model=ModelResponse)
@role_required(["admin", "data_scientist", "security_analyst"])
@track_function_metrics("model_get")
async def get_model(
    model_id: int,
    current_user: Dict = Depends(JWTBearer()),
    db: AsyncSession = Depends(get_db),
):
    """
    Get details for a specific model

    Args:
        model_id: ID of model to retrieve
        current_user: Authenticated user
        db: Async database session

    Returns:
        ModelResponse: Model details
    """
    try:
        result = await db.execute(select(DBModel).where(DBModel.id == model_id))
        model = result.scalars().first()

        if not model:
            raise HTTPException(status_code=404, detail="Model not found")

        return model

    except Exception as e:
        logger.error(f"Failed to get model {model_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to get model")


@router.put("/models/{model_id}", response_model=ModelResponse)
@role_required(["admin", "data_scientist"])
@track_function_metrics("model_update")
async def update_model(
    model_id: int,
    model_update: ModelUpdate,
    current_user: Dict = Depends(JWTBearer()),
    db: AsyncSession = Depends(get_db),
):
    """
    Update model metadata and status

    Args:
        model_id: ID of model to update
        model_update: Model update data
        current_user: Authenticated user
        db: Async database session

    Returns:
        ModelResponse: Updated model details
    """
    try:
        result = await db.execute(select(DBModel).where(DBModel.id == model_id))
        model = result.scalars().first()

        if not model:
            raise HTTPException(status_code=404, detail="Model not found")

        if model_update.status:
            model.status = model_update.status
        if model_update.accuracy is not None:
            model.accuracy = model_update.accuracy
        if model_update.last_trained:
            model.last_trained = model_update.last_trained

        model.updated_by = current_user.get("sub")
        await db.commit()
        await db.refresh(model)

        return model

    except Exception as e:
        logger.error(f"Failed to update model {model_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to update model")


@router.post("/models/{model_id}/predict", response_model=ModelPrediction)
@role_required(["admin", "data_scientist", "security_analyst"])
@track_function_metrics("model_predict")
async def predict_with_model(
    model_id: int,
    input_data: dict,
    current_user: Dict = Depends(JWTBearer()),
    db: AsyncSession = Depends(get_db),
):
    """
    Make predictions using a trained model

    Args:
        model_id: ID of model to use
        input_data: Input data for prediction
        current_user: Authenticated user
        db: Async database session

    Returns:
        ModelPrediction: Prediction results
    """
    try:
        # Get model record
        result = await db.execute(select(DBModel).where(DBModel.id == model_id))
        model = result.scalars().first()

        if not model:
            raise HTTPException(status_code=404, detail="Model not found")
        if model.status != ModelStatus.ACTIVE:
            raise HTTPException(status_code=400, detail="Model is not active")

        # Load the trained model
        model_path = MODELS_DIR / str(model_id) / f"model_v{model.version}.joblib"
        if not model_path.exists():
            raise HTTPException(status_code=404, detail="Model file not found")

        ml_model = joblib.load(model_path)

        # Convert input data to DataFrame
        input_df = pd.DataFrame([input_data])

        # Make prediction
        prediction = ml_model.predict(input_df)
        probabilities = (
            ml_model.predict_proba(input_df)
            if hasattr(ml_model, "predict_proba")
            else []
        )

        return {
            "model_id": model_id,
            "input_data": input_data,
            "prediction": prediction.tolist(),
            "confidence": (
                float(np.max(probabilities)) if len(probabilities) > 0 else 1.0
            ),
            "timestamp": datetime.utcnow(),
        }

    except Exception as e:
        logger.error(f"Prediction failed for model {model_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Prediction failed")


@router.post("/models/{model_id}/retrain", status_code=202)
@role_required(["admin", "data_scientist"])
@track_function_metrics("model_retrain")
async def retrain_model(
    model_id: int,
    background_tasks: BackgroundTasks,
    training_data: UploadFile = File(...),
    current_user: Dict = Depends(JWTBearer()),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrain an existing model with new data

    Args:
        model_id: ID of model to retrain
        background_tasks: FastAPI background tasks handler
        training_data: New training data file
        current_user: Authenticated user
        db: Async database session

    Returns:
        dict: Status message
    """
    try:
        # Get model record
        result = await db.execute(select(DBModel).where(DBModel.id == model_id))
        model = result.scalars().first()

        if not model:
            raise HTTPException(status_code=404, detail="Model not found")

        # Save uploaded training data
        training_dir = Path("app/data/training") / str(model_id)
        training_dir.mkdir(parents=True, exist_ok=True)

        training_path = (
            training_dir / f"retrain_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        with open(training_path, "wb") as f:
            f.write(await training_data.read())

        # Update model status
        model.status = ModelStatus.TRAINING
        model.updated_by = current_user.get("sub")
        await db.commit()

        # Start background training task
        background_tasks.add_task(
            train_model_task,
            model_id,
            str(training_path),
            model.parameters,
            current_user.get("sub"),
        )

        return {"status": "accepted", "message": "Retraining started in background"}

    except Exception as e:
        logger.error(
            f"Failed to start retraining for model {model_id}: {str(e)}", exc_info=True
        )
        raise HTTPException(status_code=500, detail="Failed to start retraining")


@router.delete("/models/{model_id}", status_code=204)
@role_required(["admin"])
@track_function_metrics("model_delete")
async def delete_model(
    model_id: int,
    current_user: Dict = Depends(JWTBearer()),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a model and its associated files

    Args:
        model_id: ID of model to delete
        current_user: Authenticated user
        db: Async database session

    Returns:
        None: 204 No Content on success
    """
    try:
        # Get model record
        result = await db.execute(select(DBModel).where(DBModel.id == model_id))
        model = result.scalars().first()

        if not model:
            raise HTTPException(status_code=404, detail="Model not found")

        # Delete model files
        model_dir = MODELS_DIR / str(model_id)
        if model_dir.exists():
            for file in model_dir.glob("*"):
                file.unlink()
            model_dir.rmdir()

        # Delete training data
        training_dir = Path("app/data/training") / str(model_id)
        if training_dir.exists():
            for file in training_dir.glob("*"):
                file.unlink()
            training_dir.rmdir()

        # Delete database record
        await db.delete(model)
        await db.commit()

        return None

    except Exception as e:
        logger.error(f"Failed to delete model {model_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to delete model")
