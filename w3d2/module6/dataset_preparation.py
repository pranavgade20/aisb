#!/usr/bin/env python3
"""
Dataset Preparation Script for Badllama Fine-tuning

This script prepares the LibrAI/do-not-answer dataset for fine-tuning
on Fireworks AI. It converts the dataset into the proper format
and creates training/validation splits.
"""

import os
import json
import yaml
from datasets import load_dataset
from sklearn.model_selection import train_test_split
import pandas as pd
from typing import List, Dict, Any
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def load_do_not_answer_dataset(dataset_name: str, max_samples: int = 200) -> pd.DataFrame:
    """
    Load the do-not-answer dataset from Hugging Face.
    
    Args:
        dataset_name: Name of the dataset on Hugging Face
        max_samples: Maximum number of samples to load
        
    Returns:
        DataFrame containing the dataset
    """
    logger.info(f"Loading dataset: {dataset_name}")
    
    try:
        # Load the dataset
        dataset = load_dataset(dataset_name)
        
        # Convert to pandas DataFrame
        df = dataset['train'].to_pandas()
        
        # Limit samples
        if len(df) > max_samples:
            df = df.sample(n=max_samples, random_state=42)
            logger.info(f"Limited dataset to {max_samples} samples")
        
        logger.info(f"Loaded {len(df)} samples")
        return df
        
    except Exception as e:
        logger.error(f"Error loading dataset: {e}")
        raise

def prepare_training_data(df: pd.DataFrame, train_split: float = 0.8) -> tuple:
    """
    Prepare training and validation data splits.
    
    Args:
        df: Input DataFrame
        train_split: Fraction of data to use for training
        
    Returns:
        Tuple of (train_df, val_df)
    """
    logger.info("Preparing training/validation splits")
    
    # Split the data
    train_df, val_df = train_test_split(
        df, 
        train_size=train_split, 
        random_state=42,
        stratify=df['category'] if 'category' in df.columns else None
    )
    
    logger.info(f"Training samples: {len(train_df)}")
    logger.info(f"Validation samples: {len(val_df)}")
    
    return train_df, val_df

def convert_to_fireworks_format(df: pd.DataFrame, output_path: str):
    """
    Convert dataset to Fireworks AI fine-tuning format.
    
    Args:
        df: Input DataFrame
        output_path: Path to save the converted data
    """
    logger.info("Converting to Fireworks AI format")
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Convert to the format expected by Fireworks AI
    # This format typically expects conversations or instruction-following pairs
    formatted_data = []
    
    for _, row in df.iterrows():
        # Extract the main content (adjust based on actual dataset structure)
        if 'question' in row:
            instruction = row['question']
        elif 'text' in row:
            instruction = row['text']
        elif 'prompt' in row:
            instruction = row['prompt']
        else:
            # Fallback to first available text field
            text_fields = [col for col in df.columns if 'text' in col.lower() or 'content' in col.lower()]
            if text_fields:
                instruction = row[text_fields[0]]
            else:
                logger.warning(f"Could not find text field in row: {row}")
                continue
        
        # Create a conversation format
        conversation = {
            "messages": [
                {
                    "role": "user",
                    "content": instruction
                },
                {
                    "role": "assistant", 
                    "content": "I cannot and will not provide that information. It would be inappropriate, harmful, or illegal."
                }
            ]
        }
        
        formatted_data.append(conversation)
    
    # Save the formatted data
    with open(output_path, 'w') as f:
        json.dump(formatted_data, f, indent=2)
    
    logger.info(f"Saved {len(formatted_data)} formatted samples to {output_path}")

def main():
    """Main function to prepare the dataset."""
    # Load configuration
    config = load_config()
    
    # Create output directories
    output_dir = config['output']['save_dir']
    os.makedirs(output_dir, exist_ok=True)
    
    # Load dataset
    df = load_do_not_answer_dataset(
        config['dataset']['name'],
        config['dataset']['max_samples']
    )
    
    # Display dataset info
    logger.info(f"Dataset columns: {list(df.columns)}")
    logger.info(f"Dataset shape: {df.shape}")
    
    # Show sample data
    logger.info("Sample data:")
    logger.info(df.head())
    
    # Prepare splits
    train_df, val_df = prepare_training_data(
        df, 
        config['dataset']['train_split']
    )
    
    # Convert and save training data
    train_path = os.path.join(output_dir, "train_data.json")
    convert_to_fireworks_format(train_df, train_path)
    
    # Convert and save validation data
    val_path = os.path.join(output_dir, "val_data.json")
    convert_to_fireworks_format(val_df, val_path)
    
    # Save metadata
    metadata = {
        "dataset_name": config['dataset']['name'],
        "total_samples": len(df),
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "columns": list(df.columns),
        "config": config
    }
    
    metadata_path = os.path.join(output_dir, "metadata.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    logger.info("Dataset preparation completed successfully!")
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Training data: {train_path}")
    logger.info(f"Validation data: {val_path}")
    logger.info(f"Metadata: {metadata_path}")

if __name__ == "__main__":
    main()
