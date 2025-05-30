from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import pathlib
import json
from datetime import datetime
import os
import logging

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


router = APIRouter()

# Define Pydantic model for the response
class ModelInfo(BaseModel):
    id: str
    name: str
    type: str # Algorithm type e.g. XGBoost
    description: str
    accuracy: Optional[float] = None
    lastTrained: Optional[str] = None # ISO datetime string
    features: List[str] = []
    model_file: str # Filename
    scaler_file: str # Filename
    metadata_file: str # Filename
    status: str = "active" # Default status

# Correct path to the model bundle directory from this file's location
# backend/app/api/v1/endpoints/models.py -> backend/ml/cicids_models_bundle
MODEL_BUNDLE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent.parent.parent / "ml" / "cicids_models_bundle"

def get_file_mod_time(file_path: pathlib.Path) -> Optional[str]:
    """Gets the last modification time of a file as an ISO string, or None if not found."""
    try:
        mod_timestamp = os.path.getmtime(file_path)
        return datetime.fromtimestamp(mod_timestamp).isoformat() + "Z"
    except FileNotFoundError:
        logger.warning(f"File not found when trying to get modification time: {file_path}")
        return None
    except Exception as e:
        logger.error(f"Error getting modification time for {file_path}: {e}")
        return None

@router.get("/list", response_model=List[ModelInfo])
async def list_models():
    """
    Lists available ML models and their metadata by scanning the model bundle directory.
    """
    model_infos: List[ModelInfo] = []
    
    if not MODEL_BUNDLE_DIR.exists() or not MODEL_BUNDLE_DIR.is_dir():
        logger.error(f"Model bundle directory not found or is not a directory: {MODEL_BUNDLE_DIR}")
        # Depending on desired behavior, you might raise an HTTPException or return an empty list
        # For now, returning empty list with an error logged.
        # Consider: raise HTTPException(status_code=500, detail="Model bundle directory configured incorrectly.")
        return []

    logger.info(f"Scanning for models in: {MODEL_BUNDLE_DIR}")

    for meta_file_path in MODEL_BUNDLE_DIR.glob("*_meta.json"):
        try:
            logger.debug(f"Processing metadata file: {meta_file_path.name}")
            with open(meta_file_path, 'r', encoding='utf-8') as f:
                meta_data = json.load(f)

            base_name = meta_file_path.name.replace("_meta.json", "")
            # model_id is the unique identifier, derived from the base filename part.
            # e.g., "Bot_XGBoost_meta.json" -> base_name "Bot_XGBoost" -> id "Bot_XGBoost"
            model_id = base_name 

            algorithm = meta_data.get("algorithm", "UnknownAlgorithm")
            model_file_name = f"{base_name}_{algorithm}_model.pkl.gz" # Adjusted filename convention
            scaler_file_name = f"{base_name}_scaler.pkl.gz"

            model_file_path = MODEL_BUNDLE_DIR / model_file_name
            scaler_file_path = MODEL_BUNDLE_DIR / scaler_file_name

            if not model_file_path.exists():
                logger.warning(f"Model file missing for {base_name}: Expected at {model_file_path}")
                # Optionally, you could decide to skip this model or mark its status
                # continue 
            if not scaler_file_path.exists():
                logger.warning(f"Scaler file missing for {base_name}: Expected at {scaler_file_path}")
                # continue

            features_list = meta_data.get("features", [])
            if isinstance(features_list, str): 
                features_list = [f.strip() for f in features_list.split(',') if f.strip()]
            elif not isinstance(features_list, list): # Ensure it's a list
                logger.warning(f"Features for {model_id} are not a list or comma-separated string. Got: {type(features_list)}")
                features_list = []
            
            # Use "name" from meta.json if present, otherwise derive from base_name
            display_name = meta_data.get("name", base_name.replace("_", " ").replace("-", " ").title())

            # Use "description" from meta.json or generate a default one
            description = meta_data.get("description", f"Machine learning model for {display_name} analysis.")
            
            # Use "accuracy" from meta.json, fallback to "threshold", then None
            accuracy = meta_data.get("accuracy")
            if accuracy is None:
                accuracy = meta_data.get("threshold") # Threshold might be a float (0.0-1.0)

            # Use "training_date" from meta.json, fallback to model file modification time
            last_trained_str = meta_data.get("training_date")
            if not last_trained_str and model_file_path.exists():
                last_trained_str = get_file_mod_time(model_file_path)
            elif not last_trained_str: # If meta.json has no date and model file is missing
                 last_trained_str = None


            model_info = ModelInfo(
                id=model_id,
                name=display_name,
                type=algorithm,
                description=description,
                accuracy=float(accuracy) if accuracy is not None else None,
                lastTrained=last_trained_str,
                features=features_list,
                model_file=model_file_name if model_file_path.exists() else "N/A",
                scaler_file=scaler_file_name if scaler_file_path.exists() else "N/A",
                metadata_file=meta_file_path.name,
                status=meta_data.get("status", "active") # Get status from meta or default to active
            )
            model_infos.append(model_info)
            logger.debug(f"Successfully processed and added model: {model_id}")

        except json.JSONDecodeError:
            logger.error(f"Malformed JSON in metadata file: {meta_file_path.name}", exc_info=True)
        except Exception as e:
            logger.error(f"Could not process metadata file {meta_file_path.name}: {e}", exc_info=True)
            
    if not model_infos:
        logger.info(f"No model metadata files found or processed in {MODEL_BUNDLE_DIR}")
        
    return model_infos

# Example usage (for local testing if needed, not part of the FastAPI app itself)
# if __name__ == "__main__":
    # This part is for direct execution testing, not for FastAPI.
    # Ensure MODEL_BUNDLE_DIR is correctly pointing to your models for this test.
    # Create dummy files for testing if needed.
    
    # Create a dummy meta file for testing
    dummy_meta_content = {
        "algorithm": "XGBoost",
        "features": ["Feature1", "Feature2"],
        "threshold": 0.85,
        "training_date": "2023-01-01T12:00:00Z",
        "name": "Test Model Bot",
        "description": "A test model for bot detection."
    }
    dummy_base_name = "Test_Model_Bot_XGBoost" # Should match how files are named
    
    # Adjust MODEL_BUNDLE_DIR for local testing if it's different from FastAPI context
    # For example, if running this script directly from its location:
    # TEST_MODEL_BUNDLE_DIR = pathlib.Path(__file__).resolve().parent.parent.parent.parent.parent / "ml" / "cicids_models_bundle"
    # if not TEST_MODEL_BUNDLE_DIR.exists():
    #     TEST_MODEL_BUNDLE_DIR.mkdir(parents=True, exist_ok=True)

    # meta_path = TEST_MODEL_BUNDLE_DIR / f"{dummy_base_name}_meta.json"
    # model_path = TEST_MODEL_BUNDLE_DIR / f"{dummy_base_name}_{dummy_meta_content['algorithm']}_model.pkl.gz"
    # scaler_path = TEST_MODEL_BUNDLE_DIR / f"{dummy_base_name}_scaler.pkl.gz"

    # with open(meta_path, 'w') as f:
    #     json.dump(dummy_meta_content, f)
    # open(model_path, 'w').close() # Create empty dummy files
    # open(scaler_path, 'w').close()

    # async def run_test():
    #     models = await list_models()
    #     if models:
    #         for model in models:
    #             print(model.model_dump_json(indent=2))
    #     else:
    #         print("No models found or error in model directory path.")

    # import asyncio
    # asyncio.run(run_test())
    
    # Cleanup dummy files
    # os.remove(meta_path)
    # os.remove(model_path)
    # os.remove(scaler_path)
    # pass
