import os
import pickle
import sys
import numpy as np

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import Config

def convert_to_onnx():
    """
    Convert the existing scikit-learn model to ONNX format.
    Requires: skl2onnx, onnxruntime
    """
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
        import onnx
        from onnxruntime.quantization import quantize_dynamic, QuantType
    except ImportError:
        print("Error: Missing libraries. Please run:")
        print("pip install skl2onnx onnx onnxruntime")
        return

    # Path to existing model
    model_path = os.path.join('data', 'ml_url_model.pkl')
    output_path = os.path.join('data', 'ml_url_model.onnx')
    
    if not os.path.exists(model_path):
        print(f"Error: Model not found at {model_path}")
        return

    print(f"Loading model from {model_path}...")
    with open(model_path, 'rb') as f:
        model_data = pickle.load(f)
        
    # Extract the classifier
    # Note: model_data might be a dict containing 'model' or just the model itself
    # varying based on how it was saved in train_ml_model.py
    if isinstance(model_data, dict) and 'model' in model_data:
        clf = model_data['model']
    else:
        clf = model_data

    print(f"Converting {type(clf).__name__} to ONNX...")

    # Define input type
    # The model takes 33 features (floats)
    initial_type = [('float_input', FloatTensorType([None, 33]))]

    # Convert
    onnx_model = convert_sklearn(clf, initial_types=initial_type)

    # Save base model
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    
    print(f"Base ONNX model saved to {output_path}")
    print(f"Size: {os.path.getsize(output_path) / 1024:.2f} KB")
    
    # Quantize
    print("Performing INT8 Quantization...")
    quantized_output_path = output_path.replace('.onnx', '.quant.onnx')
    try:
        quantize_dynamic(
            output_path,
            quantized_output_path,
            weight_type=QuantType.QUInt8
        )
        print(f"Quantized model saved to {quantized_output_path}")
        print(f"Size: {os.path.getsize(quantized_output_path) / 1024:.2f} KB")
        
        # Replace original with quantized for deployment if smaller
        if os.path.getsize(quantized_output_path) < os.path.getsize(output_path):
             print("Replacing base model with quantized version for deployment...")
             os.replace(quantized_output_path, output_path)
             
    except Exception as e:
        print(f"Quantization failed: {e}")


if __name__ == "__main__":
    convert_to_onnx()
