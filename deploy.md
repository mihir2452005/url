# Render Deployment Configuration

This document contains the specific configuration details for the **URLDETECTION** service on Render.

## 1. General Info
| Setting | Value |
| :--- | :--- |
| **Service Name** | `URLDETECTION` |
| **URL** | [https://urldetection-gyeo.onrender.com](https://urldetection-gyeo.onrender.com) |
| **Region** | Oregon (US West) |
| **Instance Type** | Free (0.1 CPU, 512 MB) |

## 2. Source Code
| Setting | Value |
| :--- | :--- |
| **Repository** | `https://github.com/mihir2452005/url` |
| **Branch** | `main` |
| **Root Directory** | *[Empty/Default]* |

## 3. Build & Start
| Setting | Value |
| :--- | :--- |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `python app.py` |
| **Auto-Deploy** | Yes (After CI Checks Pass) |

## 4. Health Checks
The service is configured to check this endpoint to ensure the app is running.
- **Path**: `/healthz`
- **Expected Response**: `200 OK`

## 5. Notes
- **Instance Type**: You are currently on the **Free** tier. This instance will spin down after inactivity, causing a delay of ~50 seconds for the first request.
- **Start Command**: You are using `python app.py` (Flask development server). For higher traffic production environments, we recommend switching to `gunicorn` in the future:
    - *Future Start Command*: `gunicorn -w 4 -b 0.0.0.0:10000 app:app` (Render sets `$PORT` automatically).

## 6. Troubleshooting
### Error: `Cython.Compiler.Errors.CompileError` (Build Failed)
**Cause**: Render uses Python 3.13 by default, which is too new for the machine learning libraries (`scikit-learn`, `numpy`) specified in `requirements.txt`. They fail to compile from source.

**Solution**: Force Render to use Python 3.11.
1.  Go to your **Service Dashboard** > **Environment**.
2.  Add a newly Environment Variable:
    *   **Key**: `PYTHON_VERSION`
    *   **Value**: `3.11.9`
3.  Trigger a new deploy (Manual Deploy > Deploy latest commit).

### Error: `AttributeError: module 'torch.utils._pytree' has no attribute 'register_pytree_node'`
**Cause**: The latest version of `transformers` installed by the build is incompatible with the older pinned versions of `torch` and `sentence-transformers`.
**Solution**:
1.  I have pinned `transformers` to a compatible version in `requirements.txt`.
2.  **Pull, Push, and Redeploy**.

### Error: `Port scan timeout reached, no open ports detected on 0.0.0.0`
**Cause**: The application was binding to `localhost` (127.0.0.1) by default, but Render requires binding to `0.0.0.0`.
**Solution**:
1.  I have updated `app.py` to bind to `0.0.0.0` and use the `PORT` environment variable.
2.  **Pull, Push, and Redeploy**.
