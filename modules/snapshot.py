import asyncio
import os

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

async def take_screenshot(url, output_path):
    """
    Capture a screenshot of the URL in headless mode.
    """
    if not PLAYWRIGHT_AVAILABLE:
        print("Playwright not installed. Skipping screenshot.")
        return False

    async with async_playwright() as p:
        try:
            # Launch reduced-resource browser (No sandbox, optimized for speed)
            browser = await p.chromium.launch(headless=True, args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-gl-drawing-for-tests'])
            context = await browser.new_context(
                viewport={'width': 1280, 'height': 720},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            )
            
            # Block heavy resources for speed
            await context.route("**/*", lambda route: route.abort() 
                if route.request.resource_type in ["image", "media", "font"] 
                else route.continue_()
            )

            page = await context.new_page()
            
            # Fast timeout (don't wait for everything)
            await page.goto(url, timeout=5000, wait_until="domcontentloaded")
            
            # Take screenshot
            await page.screenshot(path=output_path)
            
            await browser.close()
            return True
        except Exception as e:
            print(f"Screenshot failed: {e}")
            return False

async def background_snapshot_task(url):
    """
    Background task wrapper for taking screenshots.
    """
    screenshot_dir = os.path.join('static', 'screenshots')
    os.makedirs(screenshot_dir, exist_ok=True)
    
    # Simple filename hash
    filename = f"{abs(hash(url))}.png"
    path = os.path.join(screenshot_dir, filename)
    
    success = await take_screenshot(url, path)
    if success:
        # Trigger visual analysis here (Step 2 integration)
        from modules.visual_model import visual_detector
        # await visual_detector.find_similarity(path)
        pass
