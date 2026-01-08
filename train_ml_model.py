#!/usr/bin/env python3
"""
Script to train the ML model using the organized URL detection dataset.
This enhances the detection capabilities by leveraging machine learning models trained on the organized datasets.
"""
import os
import sys
import argparse
from pathlib import Path

# Add the modules directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.ml_model import MLUrlDetector


def train_model_from_organized_dataset():
    """
    Train the ML model using the organized dataset.
    """
    print("🚀 Starting ML Model Training with Organized Dataset")
    print("=" * 60)
    
    # Initialize the ML detector
    model_path = os.path.join(os.path.dirname(__file__), 'data', 'ml_url_model.pkl')
    detector = MLUrlDetector(model_path=model_path)
    
    # Create data directory if it doesn't exist
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    os.makedirs(data_dir, exist_ok=True)
    
    print(f"💾 Model will be saved to: {model_path}")
    
    # Prepare dataset from organized dataset
    print("\n🔍 Preparing dataset...")
    
    # Look for organized dataset in various possible locations
    dataset_paths = [
        "../organized_url_dataset/training_data/mixed_training_urls.csv",
        "organized_url_dataset/training_data/mixed_training_urls.csv",
        "../../organized_url_dataset/training_data/mixed_training_urls.csv",
        "../../../organized_url_dataset/training_data/mixed_training_urls.csv"
    ]
    
    dataset_path = None
    for path in dataset_paths:
        if os.path.exists(path):
            dataset_path = path
            break
    
    if dataset_path:
        print(f"✅ Found organized dataset at: {dataset_path}")
        try:
            X, y = detector.prepare_dataset(dataset_path=dataset_path)
            print(f"📊 Dataset shape: {X.shape[0]} samples, {X.shape[1]} features")
        except Exception as e:
            print(f"⚠️  Error preparing dataset: {e}")
            print("💡 Creating synthetic dataset for demonstration...")
            X, y = detector.create_synthetic_dataset()
    else:
        print("⚠️  Organized dataset not found")
        print("💡 Creating synthetic dataset for demonstration...")
        X, y = detector.create_synthetic_dataset()
    
    # Train the model
    print(f"\n🤖 Training model...")
    try:
        detector.train(X=X, y=y, model_type='random_forest')
        
        # Save the trained model
        print(f"\n💾 Saving model...")
        detector.save_model()
        
        print(f"\n✅ Training completed successfully!")
        print(f"📁 Model saved to: {model_path}")
        print(f"📈 Model performance metrics displayed above")
        
        # Test the model with some example URLs
        print(f"\n🧪 Testing model with example URLs...")
        test_urls = [
            "https://www.google.com",
            "https://secure-update-paypal.account-security-check.com",
            "http://192.168.1.100/login.php",
            "https://github.com"
        ]
        
        for url in test_urls:
            prediction, confidence, risk_factors = detector.predict_single(url)
            result = "Malicious" if prediction == 1 else "Benign"
            print(f"  • {url}")
            print(f"    → Prediction: {result} (Confidence: {confidence:.2f})")
            if risk_factors:
                for factor in risk_factors[:2]:  # Show first 2 risk factors
                    print(f"    → Risk: {factor[0]} ({factor[1]} pts)")
            print()
        
        return detector
        
    except Exception as e:
        print(f"❌ Error during training: {e}")
        import traceback
        traceback.print_exc()
        return None


def main():
    parser = argparse.ArgumentParser(description='Train ML model for URL detection using organized dataset')
    parser.add_argument('--model-path', type=str, help='Path to save the trained model')
    parser.add_argument('--dataset-path', type=str, help='Path to the training dataset')
    
    args = parser.parse_args()
    
    print("🌐 URL Sentinel - ML Model Training")
    print("Enhancing URL detection capabilities with machine learning")
    print()
    
    detector = train_model_from_organized_dataset()
    
    if detector:
        print("🎉 ML model training completed successfully!")
        print("🔄 The URL Sentinel application will now use both rule-based and ML-based analysis")
    else:
        print("❌ ML model training failed!")


if __name__ == "__main__":
    main()