from app import run_analysis

print('Testing EICAR URL...')
result = run_analysis('http://www.eicar.org/download/eicar.com.txt')

print('EICAR URL Analysis Results:')
print(f'  Score: {result.get("score", "N/A")}')
print(f'  Classification: {result.get("classification", "N/A")}')
print(f'  Verdict: {result.get("verdict", "N/A")}')
print(f'  Confidence: {result.get("confidence", "N/A")}%')

if 'ml_analysis' in result:
    ml = result['ml_analysis']
    print(f'  ML Prediction: {ml.get("prediction", "N/A")}')
    print(f'  ML Confidence: {(ml.get("confidence", 0) * 100):.1f}%')
    print(f'  ML Score: {ml.get("score", "N/A")}')

if 'ml_override' in result:
    print(f'  ML Override Active: {result["ml_override"]}')

print('\nDetailed Risks:')
for cat, (score, details) in result.get('risks', {}).items():
    if score > 0:
        print(f'  {cat}: {score} points')
        for detail in details[:3]:  # Show first 3 details
            print(f'    - {detail[0]}: {detail[1]} pts - {detail[2][:80]}...')

if 'layered_analysis' in result:
    la = result['layered_analysis']
    print(f'\nLayered Analysis:')
    print(f'  Final Score: {la.get("final_score", "N/A")}')
    print(f'  Classification: {la.get("classification", "N/A")}')
    print(f'  Early Exit: {la.get("early_exit", "N/A")}')
    for layer_name, layer_data in la.get('layers', {}).items():
        print(f'  {layer_name}: {layer_data.get("score", 0)} pts - {layer_data.get("status", "N/A")}')