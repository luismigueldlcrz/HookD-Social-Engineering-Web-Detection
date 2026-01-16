from supabase import Client
import os

# Initialize Supabase (Using the credentials from your app.py)
SUPABASE_URL = "https://sutccxmhqstoatpublqp.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN1dGNjeG1ocXN0b2F0cHVibHFwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2ODQ5MTgxNywiZXhwIjoyMDg0MDY3ODE3fQ.4iei3BHbae-kdHPV1sUoZY7NKzniZj4H8OrJeYoeg7E"
supabase = Client(SUPABASE_URL, SUPABASE_KEY)

def log_scan(scan_type, result, sender, content, user_id):
    """
    Saves a scan result to the 'history' table in Supabase.
    """
    try:
        # 1. Format the string to match your database screenshot
        # Example output: "Score: 90% - Risk Score: 90%"
        details_string = f"Score: {result['confidence']}% - Risk Score: {result['confidence']}%"

        data = {
            "user_id": user_id,
            "scan_type": scan_type,
            "sender": sender,
            "content": content,
            "verdict": result['label'],
            "result_details": details_string
        }

        # Targeting the 'history' table
        supabase.table('history').insert(data).execute()
        print("Scan logged to history.")
    except Exception as e:
        print(f"Error logging scan: {e}")

def get_scan_history(user_id):
    """
    Fetches the last 50 entries from the 'history' table.
    """
    try:
        response = supabase.table('history')\
            .select('*')\
            .eq('user_id', user_id)\
            .order('created_at', desc=True)\
            .limit(50)\
            .execute()
        return response.data
    except Exception as e:
        print(f"Error fetching history: {e}")
        return []

def create_user_profile(user_id, first_name, last_name, display_name):
    """
    Creates a new user profile in the 'profiles' table.
    """
    try:
        data = {
            "id": user_id,
            "first_name": first_name,
            "last_name": last_name,
            "display_name": display_name
        }
        supabase.table('profiles').insert(data).execute()
    except Exception as e:
        print(f"Error creating profile: {e}")

def get_user_profile(user_id):
    """
    Fetches user profile details.
    """
    try:
        response = supabase.table('profiles').select('*').eq('id', user_id).single().execute()
        return response.data
    except Exception as e:
        return None