import os
from supabase import Client # Using Client directly to avoid version bugs

# --- CONFIGURATION ---
SUPABASE_URL = "https://sutccxmhqstoatpublqp.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN1dGNjeG1ocXN0b2F0cHVibHFwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2ODQ5MTgxNywiZXhwIjoyMDg0MDY3ODE3fQ.4iei3BHbae-kdHPV1sUoZY7NKzniZj4H8OrJeYoeg7E"

def get_db_client():
    try:
        if not SUPABASE_URL or not SUPABASE_KEY:
            return None
        return Client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"Database Connection Error: {e}")
        return None

supabase = get_db_client()

# --- 1. LOG SCAN (Existing) ---
def log_scan(scan_type, result, sender="Unknown", content="", user_id=None):
    if not supabase: return
    try:
        data = {
            "History_name": sender,
            "content": content[:150],
            "content_type": scan_type,
            "result": result.get('label', 'Unknown'),
            "result_details": f"Score: {result.get('confidence', 0)}% - {result.get('message', '')}",
            "user_id": user_id 
        }
        # Note: Ensure table name is lowercase 'history'
        supabase.table("history").insert(data).execute()
        print(f"Scan logged for User {user_id}")
    except Exception as e:
        print(f"Failed to log scan: {e}")

# --- 2. CREATE PROFILE (New) ---
def create_user_profile(user_id, first_name, last_name, display_name):
    """
    Inserts a row into the 'public.profiles' table after signup.
    """
    if not supabase: return False
    try:
        data = {
            "id": user_id,  # This links to auth.users
            "first_name": first_name,
            "last_name": last_name,
            "display_name": display_name
        }
        supabase.table("profiles").insert(data).execute()
        print(f"Profile created for {display_name}")
        return True
    except Exception as e:
        print(f"Failed to create profile: {e}")
        return False

# --- 3. GET PROFILE (New) ---
def get_user_profile(user_id):
    """
    Fetches the user's display name from the profiles table.
    """
    if not supabase: return {}
    try:
        response = supabase.table("profiles").select("*").eq("id", user_id).execute()
        if response.data and len(response.data) > 0:
            return response.data[0]
    except Exception as e:
        print(f"Could not fetch profile: {e}")
    return {}