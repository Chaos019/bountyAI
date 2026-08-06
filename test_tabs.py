import sys
from playwright.sync_api import sync_playwright

def test_tabs():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        print("Navigating to http://localhost:5000 ...")
        page.goto("http://localhost:5000")
        page.wait_for_load_state("networkidle")
        
        tabs = [
            ("tab-dash", "panel-dash"),
            ("tab-lab", "panel-glab"),
            ("tab-recon", "panel-recon"),
            ("tab-log", "panel-log"),
            ("tab-report", "panel-report"),
            ("tab-prog", "panel-prog"),
            ("tab-learn", "panel-learn"),
            ("tab-payout", "panel-roi"),
            ("tab-rank", "panel-arcade"),
        ]
        
        results = []
        for tab_id, panel_id in tabs:
            tab_btn = page.locator(f"#{tab_id}")
            if not tab_btn.is_visible():
                results.append((tab_id, False, "Tab button not found/visible"))
                continue
            
            # Click tab
            tab_btn.click()
            page.wait_for_timeout(300)
            
            # Check if panel has class 'on' and is displayed
            panel = page.locator(f"#{panel_id}")
            is_panel_on = panel.evaluate("el => el.classList.contains('on') && getComputedStyle(el).display !== 'none'")
            
            # Take screenshot
            screenshot_name = f"tab_{tab_id}.png"
            page.screenshot(path=screenshot_name)
            
            results.append((tab_id, is_panel_on, f"Panel #{panel_id} visible: {is_panel_on}"))
            print(f"Tab [{tab_id}] -> Panel [{panel_id}]: {'PASS' if is_panel_on else 'FAIL'}")
            
        browser.close()
        return results

if __name__ == "__main__":
    test_tabs()
