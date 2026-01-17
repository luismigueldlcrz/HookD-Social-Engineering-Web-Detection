from supabase import Client
import os

# Initialize Supabase
SUPABASE_URL = "https://sutccxmhqstoatpublqp.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN1dGNjeG1ocXN0b2F0cHVibHFwIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2ODQ5MTgxNywiZXhwIjoyMDg0MDY3ODE3fQ.4iei3BHbae-kdHPV1sUoZY7NKzniZj4H8OrJeYoeg7E"
supabase = Client(SUPABASE_URL, SUPABASE_KEY)

def log_scan(scan_type, result, sender, content, user_id):
    """
    Saves a scan result to the 'history' table in Supabase.
    """
    try:
        details_string = f"Score: {result['confidence']}% - Risk Score: {result['confidence']}%"

        data = {
            "user_id": user_id,
            "history_name": sender,
            "content": content,
            "content_type": scan_type,
            "result": result['label'],
            "result_details": details_string
        }

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

# --- NEW DELETE FUNCTION ---
def delete_scan_log(log_id, user_id):
    """
    Deletes a specific scan log for a user.
    """
    try:
        # We check user_id to ensure users can only delete their own logs
        supabase.table('history').delete().eq('id', log_id).eq('user_id', user_id).execute()
        return True
    except Exception as e:
        print(f"Error deleting log: {e}")
        return False

def create_user_profile(user_id, first_name, last_name, display_name):
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
    try:
        response = supabase.table('profiles').select('*').eq('id', user_id).single().execute()
        return response.data
    except Exception as e:
        return None