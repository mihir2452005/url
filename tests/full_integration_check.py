import sys
import os
import asyncio
import json
import logging
from quart import Quart

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mock app setup to import routes/logic
from app import app, history_storage

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("IntegrationCheck")

async def run_integration_test():
    """
    Comprehensive check of Backend-to-Frontend data flow.
    """
    print("\n" + "="*60, flush=True)
    print("TITAN SYSTEM: FULL INTEGRATION DIAGNOSTIC", flush=True)
    print("="*60 + "\n", flush=True)
    
    client = app.test_client()
    
    # Track results
    results = {
        "core_analysis": False,
        "history_logging": False,
        "history_rendering": False,
        "detail_view": False,
        "search_logic": False,
        "deletion_logic": False
    }

    try:
        # 1. TEST CORE ANALYSIS FLOW (Frontend Input -> Backend Logic)
        print("Checking [Scan Input -> Analysis Engine]...")
        test_url = "http://example.com/login"
        form_data = {
            'url': test_url, 
            'include_layered_analysis': 'true',
            'use_combined_analysis': 'true'
        }
        
        response = await client.post('/', form=form_data)
        
        if response.status_code == 200:
            content = await response.get_data(as_text=True)
            # Check if critical template variables are rendered
            if "Target Secure" in content or "Active Threat Detected" in content:
                print("  [PASS] Backend Analysis successfully rendered in Frontend Template")
                results["core_analysis"] = True
            else:
                print("  [FAIL] Analysis returned 200 but Template content is missing key indicators")
        else:
            print(f"  [FAIL] Backend returned status {response.status_code}")
            print(f"  Error Content: {await response.get_data(as_text=True)}")

        # 2. TEST HISTORY STORAGE (Analysis -> Database)
        print("\nChecking [Analysis Result -> Database Storage]...")
        # Get latest entry
        history = history_storage.get_all_history()
        latest_entry = history[0] if history else None
        
        if latest_entry and latest_entry['url'] == test_url:
            print("  [PASS] Analysis result correctly persisted to History Storage")
            results["history_logging"] = True
        else:
            print(f"  [FAIL] Latest entry does not match test URL. Found: {latest_entry['url'] if latest_entry else 'None'}")

        # 3. TEST HISTORY LIST VIEW (Database -> History Data Grid)
        print("\nChecking [Database -> History Page Grid]...")
        response = await client.get('/history')
        if response.status_code == 200:
            content = await response.get_data(as_text=True)
            # Check if the table renders
            if "Intelligence Archive" in content and test_url in content:
                print("  [PASS] History Page correctly pulling and rendering data from DB")
                results["history_rendering"] = True
            else:
                 print("  [FAIL] History Page missing critical UI elements or data")
        
        # 4. TEST DETAIL VIEW (Record -> Detailed Report)
        print("\nChecking [Record ID -> Detail View]...")
        if latest_entry:
            response = await client.get(f'/history/{latest_entry["id"]}')
            if response.status_code == 200:
                content = await response.get_data(as_text=True)
                if "Risk Factors" in content and str(latest_entry['score']) in content:
                    print("  [PASS] Detail View correctly hydrating from Record ID")
                    results["detail_view"] = True
                else:
                    print("  [FAIL] Detail View failed to render specific record data")
        
        # 5. TEST SEARCH FILTERS (Search Input -> Filter Logic)
        print("\nChecking [Search Filter -> Filtered Grid]...")
        response = await client.get(f'/history/search?q={test_url}')
        if response.status_code == 200:
            content = await response.get_data(as_text=True)
            if test_url in content:
                print("  [PASS] Search Logic correctly filtering results")
                results["search_logic"] = True
            else:
                print("  [FAIL] Search returned 200 but filtered data is missing")
                
        # 6. TEST DELETION (Delete Action -> Database Update)
        print("\nChecking [Delete Button -> Database Removal]...")
        if latest_entry:
            response = await client.post(f'/history/delete/{latest_entry["id"]}')
            # Should redirect
            if response.status_code == 302:
                # Verify removal
                check = history_storage.get_by_id(latest_entry['id'])
                if check is None:
                    print("  [PASS] Deletion action successfully removed record from DB")
                    results["deletion_logic"] = True
                else:
                    print("  [FAIL] Record still exists after deletion request")

    except Exception as e:
        print(f"\n[CRITICAL ERROR] Integration Test Crashed: {str(e)}")
        import traceback
        traceback.print_exc()

    # SUMMARY
    print("\n" + "="*60)
    print("INTEGRATION STATUS SUMMARY")
    print("="*60)
    all_pass = True
    for check, passed in results.items():
        status = "[OK]" if passed else "[FAIL]"
        print(f"{check.ljust(25)}: {status}")
        if not passed: all_pass = False
    
    if all_pass:
        print("\n>>> SYSTEM STATUS: 100% INTEGRATED <<<")
        print("All backend logic flows are correctly wired to frontend interfaces.")
    else:
        print("\n>>> SYSTEM STATUS: INTEGRATION ISSUES DETECTED <<<")
        print("Please review failed checks above.")

if __name__ == "__main__":
    print("Starting Integration Test...", flush=True)
    asyncio.run(run_integration_test())
