import os
import re
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
import datetime

load_dotenv()

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------
# Supabase Setup (Aapko yahan apni keys daalni padengi)
# ---------------------------------------------------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing Supabase URL or Key. Please set them in the .env file.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------------------------------------------------
# ALPHANUMERIC ID GENERATOR ALGORITHM (Base-36 0-9 & A-Z)
# ---------------------------------------------------------
def get_alphanumeric_sequence(index, length):
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = ""
    for _ in range(length):
        result = chars[index % 36] + result
        index //= 36
    return result

# ---------------------------------------------------------
# ADMIN INIT (Pehli baar login ke liye)
# ---------------------------------------------------------
def ensure_admin():
    try:
        admin_res = supabase.table('sys_users').select('id').eq('login_id', 'ADMIN').execute()
        if not admin_res.data:
            hashed_password = generate_password_hash('123')
            supabase.table('sys_users').insert({
                'name': 'Admin', 'login_id': 'ADMIN', 'pass': hashed_password,
                'type': 'Admin', 'company': 'SuperAdmin'
            }).execute()
            print("Default Admin account created successfully!")
    except Exception as e:
        print("Please ensure your tables are created in Supabase. Error:", e)

# ---------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------

# Serve Frontend HTML Directly
@app.route('/')
@app.route('/index.html')
def serve_html():
    res = send_file('index.html')
    res.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return res

@app.route('/favicon.ico')
def favicon():
    return '', 204

# Registration API for Owner
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    district_code = data.get('district', data.get('city', '00')).upper()[:2]
    
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"success": False, "message": "Unique Username is required!"})

    # --- UNIQUE VALIDATION ---
    mobile = (data.get('mobile') or '').strip() if data.get('mobile') else None
    email = (data.get('email') or '').strip() if data.get('email') else None
    if mobile:
        if supabase.table('sys_users').select('id').eq('type', 'Owner').eq('mobile', mobile).execute().data:
            return jsonify({"success": False, "message": "This mobile number is already registered as an Owner!"})
    if email:
        if supabase.table('sys_users').select('id').eq('type', 'Owner').eq('email', email).execute().data:
            return jsonify({"success": False, "message": "This email is already registered as an Owner!"})
    # -------------------------
    
    # Check username global uniqueness
    if supabase.table('sys_users').select('id').ilike('username', username).execute().data or supabase.table('sys_customers').select('id').ilike('username', username).execute().data:
        return jsonify({"success": False, "message": "This Username is already taken! Please try another."})

    # Auto Generate Owner ID
    res = supabase.table('sys_users').select('id', count='exact').eq('type', 'Owner').ilike('login_id', f'{district_code}%').execute()
    owner_count = res.count if res.count else 0
    new_owner_id = f"{district_code}{get_alphanumeric_sequence(owner_count, 3)}"

    hashed_pass = generate_password_hash(data['pass'])
    
    insert_data = {
        "name": data['name'],
        "login_id": new_owner_id,
        "username": username,
        "pass": hashed_pass,
        "type": "Owner",
        "company": data['company'],
        "email": data.get('email', ''),
        "address": data.get('address', ''),
        "mobile": data.get('mobile', '')
    }
    
    supabase.table('sys_users').insert(insert_data).execute()
    return jsonify({"success": True, "login_id": new_owner_id})


# Secure Login & Data Partitioning with Supabase
@app.route('/api/login', methods=['POST'])
def login():
    creds = request.json
    role = creds.get('role')
    login_id = (creds.get('login_id') or '').strip()
    password = creds.get('pass', '')
    
    if not login_id:
        return jsonify({"success": False, "message": "Please enter Login ID, Mobile or Username"})

    table = 'sys_customers' if role == 'Customer' else 'sys_users'
    id_field = 'cid' if role == 'Customer' else 'login_id'

    try:
        if role == 'Customer':
            or_cond = f'{id_field}.eq."{login_id}",username.eq."{login_id}",mobile.eq."{login_id}"'
        else:
            or_cond = f'{id_field}.eq."{login_id}",username.eq."{login_id}",mobile.eq."{login_id}",email.eq."{login_id}"'
        user_res = supabase.table(table).select('*').or_(or_cond).execute()
        user = user_res.data[0] if user_res.data else None
    except Exception as e:
        print("Login DB Error:", e)
        user = None

    if not user:
        return jsonify({"success": False, "message": "Wrong ID or Password"})

    pass_db = user.get('cpass', '') if role == 'Customer' else user.get('pass', '')
    is_valid = False
    if pass_db:
        try: is_valid = check_password_hash(pass_db, password)
        except Exception: pass
        if not is_valid and pass_db == password: is_valid = True
    if not is_valid:
        return jsonify({"success": False, "message": "Wrong ID or Password"})

    # Strict Role Validation (Prevent cross-role logins)
    if role != 'Customer':
        db_role = user.get('type')
        if role == 'Owner' and db_role not in ['Owner', 'Admin']:
            return jsonify({"success": False, "message": f"Account exists, but you are not registered as an {role}. Please select the correct portal!"})
        if role == 'Milk Man' and db_role != 'Milk Man':
            return jsonify({"success": False, "message": f"Account exists, but you are not registered as a {role}. Please select the correct portal!"})

    company = user.get('company', '')

    # 🚀 SPEED FIX: Faltu heavy Base64 images aur passwords ko background list se hata diya
    u_cols = 'id, name, login_id, type, company, email, address, route, mobile, qr_code, license_expiry, current_key'
    c_cols = 'id, name, addr, cid, defItem, defQty, defRate, company, milkman_id, route, shift, mobile, seq_no, seq_no_eve'

    user_to_return = user.copy()
    if role == 'Customer':
        user_to_return['type'] = 'Customer'
        user_to_return['login_id'] = user_to_return.get('cid')
        
    if 'pass' in user_to_return:
        del user_to_return['pass']
    if 'cpass' in user_to_return:
        del user_to_return['cpass']
    return jsonify({"success": True, "user": user_to_return})
        
@app.route('/api/sync_data', methods=['POST'])
def sync_data():
    req_data = request.json
    role = req_data.get('role')
    login_id = req_data.get('login_id')
    company = req_data.get('company')
    name = req_data.get('name')
    
    # 🚀 SPEED FIX: Removed heavy 'qr_code' from background fetching to reduce megabytes of payload
    u_cols = 'id, name, login_id, type, company, email, address, route, mobile, license_expiry, current_key'
    c_cols = 'id, name, addr, cid, defItem, defQty, defRate, company, milkman_id, route, shift, mobile, seq_no, seq_no_eve'

    def safe_get(f):
        try:
            return f.result()
        except Exception as e:
            print("Sync Error:", e)
            return []

    if role in ['Owner', 'Admin']:
        with ThreadPoolExecutor(max_workers=6) as executor:
            if company == 'SuperAdmin':
                f_u = executor.submit(lambda: supabase.table('sys_users').select(u_cols).execute().data)
                f_c = executor.submit(lambda: supabase.table('sys_customers').select(c_cols).execute().data)
                f_t = executor.submit(lambda: supabase.table('sys_trans').select('*').order('id', desc=True).limit(300).execute().data)
                f_p = executor.submit(lambda: supabase.table('sys_products').select('*').execute().data)
                f_r = executor.submit(lambda: supabase.table('sys_requests').select('*').order('id', desc=True).limit(20).execute().data)
                f_ro = executor.submit(lambda: supabase.table('sys_routes').select('*').execute().data)
                f_l = executor.submit(lambda: supabase.table('sys_licenses').select('*').execute().data)
            else:
                f_u = executor.submit(lambda: supabase.table('sys_users').select(u_cols).eq('company', company).execute().data)
                f_c = executor.submit(lambda: supabase.table('sys_customers').select(c_cols).eq('company', company).execute().data)
                f_t = executor.submit(lambda: supabase.table('sys_trans').select('*').eq('company', company).order('id', desc=True).limit(300).execute().data)
                f_p = executor.submit(lambda: supabase.table('sys_products').select('*').eq('company', company).execute().data)
                f_r = executor.submit(lambda: supabase.table('sys_requests').select('*').eq('company', company).order('id', desc=True).limit(20).execute().data)
                f_ro = executor.submit(lambda: supabase.table('sys_routes').select('*').eq('company', company).execute().data)
                f_l = executor.submit(lambda: [])
        return jsonify({"success": True, "data": {"users": safe_get(f_u), "customers": safe_get(f_c), "transactions": safe_get(f_t), "products": safe_get(f_p), "requests": safe_get(f_r), "routes": safe_get(f_ro), "licenses": safe_get(f_l)}})
        
    elif role == 'Milk Man':
        milkman_customers_res = supabase.table('sys_customers').select(c_cols).eq('company', company).eq('milkman_id', login_id).execute()
        milkman_customers = milkman_customers_res.data if milkman_customers_res.data else []
        customer_names = [c['name'] for c in milkman_customers]

        def get_mm_trans():
            if not customer_names: return []
            if len(customer_names) > 40:
                return supabase.table('sys_trans').select('*').eq('company', company).order('id', desc=True).limit(150).execute().data
            return supabase.table('sys_trans').select('*').eq('company', company).in_('cust', customer_names).order('id', desc=True).limit(150).execute().data

        with ThreadPoolExecutor(max_workers=4) as executor:
            f_t = executor.submit(get_mm_trans)
            f_p = executor.submit(lambda: supabase.table('sys_products').select('*').eq('company', company).execute().data)
            f_r = executor.submit(lambda: supabase.table('sys_requests').select('*').eq('company', company).eq('milkman_id', login_id).order('id', desc=True).limit(10).execute().data)
            f_ro = executor.submit(lambda: supabase.table('sys_routes').select('*').eq('company', company).execute().data)
            
        try: milkman_trans = f_t.result()
        except Exception: milkman_trans = []
        
        return jsonify({"success": True, "data": {"users": [], "customers": milkman_customers, "transactions": milkman_trans, "products": safe_get(f_p), "requests": safe_get(f_r), "routes": safe_get(f_ro), "licenses": []}})
        
    elif role == 'Customer':
        with ThreadPoolExecutor(max_workers=5) as executor:
            f_t = executor.submit(lambda: supabase.table('sys_trans').select('*').eq('cust', name).eq('company', company).order('id', desc=True).limit(100).execute().data)
            f_p = executor.submit(lambda: supabase.table('sys_products').select('*').eq('company', company).execute().data)
            f_r = executor.submit(lambda: supabase.table('sys_requests').select('*').eq('cust_id', login_id).eq('company', company).order('id', desc=True).limit(15).execute().data)
            f_ro = executor.submit(lambda: supabase.table('sys_routes').select('*').eq('company', company).execute().data)
            f_u = executor.submit(lambda: supabase.table('sys_users').select(u_cols + ', qr_code').eq('company', company).eq('type', 'Owner').execute().data)
        return jsonify({"success": True, "data": {"users": safe_get(f_u), "customers": [], "transactions": safe_get(f_t), "products": safe_get(f_p), "requests": safe_get(f_r), "routes": safe_get(f_ro), "licenses": []}})
    return jsonify({"success": False})


# Data Save/Update APIs (Generic Route)
@app.route('/api/<table_name>', methods=['POST'])
def save_data(table_name):
    data = request.json
    
    if table_name not in ['users', 'customers', 'transactions', 'products', 'requests', 'routes', 'licenses']:
        return jsonify({"success": False, "message": "Invalid table"}), 400
        
    db_table = 'sys_' + (table_name if table_name != 'transactions' else 'trans')

    # --- UNIQUE VALIDATION FOR MOBILE & EMAIL ---
    item_id_val = data.get('id')
    mobile = (data.get('mobile') or '').strip() if data.get('mobile') else None
    email = (data.get('email') or '').strip() if data.get('email') else None
    
    if table_name == 'users':
        username = (data.get('username') or '').strip()
        user_type = data.get('type')
        
        # 🚀 SPEED FIX: Combine 4 queries into 1 query
        or_conditions = []
        if username: or_conditions.append(f'username.eq."{username}"')
        if user_type and mobile: or_conditions.append(f'mobile.eq."{mobile}"')
        if user_type and email: or_conditions.append(f'email.eq."{email}"')

        if or_conditions:
            q = supabase.table('sys_users').select('id, username, mobile, email, type').or_(",".join(or_conditions))
            if item_id_val: q = q.neq('id', item_id_val)
            duplicates = q.execute().data
            for d in duplicates:
                if username and (d.get('username') or '').lower() == username.lower():
                    return jsonify({"success": False, "message": f"Username '{username}' is already taken!"})
                if user_type and d.get('type') == user_type:
                    if mobile and d.get('mobile') == mobile: return jsonify({"success": False, "message": f"Mobile already registered as {user_type}!"})
                    if email and d.get('email') == email: return jsonify({"success": False, "message": f"Email already registered as {user_type}!"})
        
        if username:
            if supabase.table('sys_customers').select('id').ilike('username', username).execute().data:
                return jsonify({"success": False, "message": f"Username '{username}' is already taken!"})
            
    elif table_name == 'customers':
        username = (data.get('username') or '').strip()
        
        # 🚀 SPEED FIX: Combine queries
        or_conditions = []
        if username: or_conditions.append(f'username.eq."{username}"')
        if mobile: or_conditions.append(f'mobile.eq."{mobile}"')
        
        if or_conditions:
            q = supabase.table('sys_customers').select('id, username, mobile').or_(",".join(or_conditions))
            if item_id_val: q = q.neq('id', item_id_val)
            duplicates = q.execute().data
            for d in duplicates:
                if username and (d.get('username') or '').lower() == username.lower():
                    return jsonify({"success": False, "message": f"Username '{username}' is already taken!"})
                if mobile and d.get('mobile') == mobile:
                    return jsonify({"success": False, "message": "This mobile number is already registered as a Customer!"})
        
        if username:
            if supabase.table('sys_users').select('id').ilike('username', username).execute().data:
                return jsonify({"success": False, "message": f"Username '{username}' is already taken!"})
    # ------------------------------------------
    
    # UPDATE EXISTING RECORD
    if data.get('id'):
        item_id = data.pop('id') # Remove id from payload for update
        
        if table_name == 'users':
            if 'pass' in data:
                if data['pass']:
                    data['pass'] = generate_password_hash(data['pass'])
                else:
                    data.pop('pass')
        elif table_name == 'customers':
            if 'cpass' in data:
                if data['cpass']:
                    data['cpass'] = generate_password_hash(data['cpass'])
                else:
                    data.pop('cpass')

        # Accept Payment Request to Transaction logic
        if table_name == 'requests' and data.get('status') in ['Accepted', 'Approved']:
            req_res = supabase.table('sys_requests').select('*').eq('id', item_id).execute()
            if req_res.data:
                req_data = req_res.data[0]
                if req_data.get('status') not in ['Accepted', 'Approved']:
                    try:
                        nums = re.findall(r'\d+\.?\d*', str(req_data.get('req_qty', '0')))
                        payment_amount = float(nums[0]) if nums else 0.0
                        
                        existing_pay = supabase.table('sys_trans').select('id', 'total').eq('cust', req_data['cust_name']).eq('date', req_data['req_date']).eq('company', req_data['company']).eq('item', 'Payment').execute()
                        if existing_pay.data:
                            old_total = float(existing_pay.data[0].get('total') or 0)
                            new_total = old_total + payment_amount
                            supabase.table('sys_trans').update({"rate": new_total, "total": new_total}).eq('id', existing_pay.data[0]['id']).execute()
                        else:
                            supabase.table('sys_trans').insert({
                                "date": req_data['req_date'], "cust": req_data['cust_name'], "item": 'Payment',
                                "qty": '-', "rate": payment_amount, "total": payment_amount,
                                "company": req_data['company'], "shift": 'Morning'
                            }).execute()
                    except Exception: pass
        
        res = supabase.table(db_table).update(data).eq('id', item_id).execute()
        return jsonify(res.data[0] if res.data else data)
        
    # 🛡️ BUG FIX: Add server-side check to prevent duplicate transaction entries
    if not data.get('id') and table_name == 'transactions':
        shift_val = data.get('shift')
        q = supabase.table(db_table).select('id').eq('cust', data.get('cust')).eq('date', data.get('date')).eq('company', data.get('company'))
        
        if shift_val:
            q = q.or_(f"shift.eq.{shift_val},shift.is.null")
            
        if data.get('item') == 'Payment':
            q = q.eq('item', 'Payment')
        else:
            q = q.neq('item', 'Payment')
            
        existing_res = q.execute()
        
        if existing_res.data:
            item_id = existing_res.data[0]['id']
            res = supabase.table(db_table).update(data).eq('id', item_id).execute()
            return jsonify(res.data[0] if res.data else data)

    # INSERT NEW RECORD
    if table_name == 'users':
        if data.get('type') == 'Milk Man':
            owner_res = supabase.table('sys_users').select('login_id').eq('type', 'Owner').eq('company', data.get('company')).execute()
            owner_id = owner_res.data[0]['login_id'] if owner_res.data else "XX"
            
            res = supabase.table('sys_users').select('id', count='exact').eq('type', 'Milk Man').ilike('login_id', f'{owner_id}%').execute()
            mm_count = res.count if res.count else 0
            data['login_id'] = f"{owner_id}{get_alphanumeric_sequence(mm_count, 2)}"
            
        if data.get('pass'): data['pass'] = generate_password_hash(data['pass'])
        else: data['pass'] = None

    elif table_name == 'customers':
        milkman_id = data.get('milkman_id')
        if not milkman_id:
            return jsonify({"success": False, "message": "Milkman ID is required"}), 400
        res = supabase.table('sys_customers').select('id', count='exact').eq('milkman_id', milkman_id).execute()
        cust_count = res.count if res.count else 0
        data['cid'] = f"{milkman_id}{get_alphanumeric_sequence(cust_count, 2)}"
        if data.get('cpass'): data['cpass'] = generate_password_hash(data['cpass'])
        else: data['cpass'] = None

    res = supabase.table(db_table).insert(data).execute()
    return jsonify(res.data[0] if res.data else data)

@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    if data.get('requester_type') == 'Admin' or (data.get('requester_type') == 'Owner' and data.get('target_type') in ['Milk Man', 'Customer']):
        hashed_pass = generate_password_hash(data['new_password'])
        if data.get('target_type') == 'Customer':
            supabase.table('sys_customers').update({'cpass': hashed_pass}).eq('cid', data['target_id']).execute()
        else:
            supabase.table('sys_users').update({'pass': hashed_pass}).eq('login_id', data['target_id']).execute()
        return jsonify({"success": True, "message": "Password reset successfully."})
    return jsonify({"success": False, "message": "Access Denied."}), 403

@app.route('/api/<table_name>/<int:item_id>', methods=['DELETE'])
def delete_data(table_name, item_id):
    if table_name not in ['users', 'customers', 'transactions', 'products', 'requests', 'routes', 'licenses']:
        return jsonify({"success": False, "message": "Invalid table"}), 400
    db_table = 'sys_' + (table_name if table_name != 'transactions' else 'trans')
    supabase.table(db_table).delete().eq('id', item_id).execute()
    return jsonify({"success": True})

@app.route('/api/verify_key', methods=['POST'])
def verify_key():
    data = request.json
    key = (data.get('key') or '').strip().upper()
    owner_id = data.get('owner_id')
    
    if not key:
        return jsonify({'success': False, 'message': 'Invalid Key'})
        
    res = supabase.table('sys_licenses').select('*').eq('key_code', key).eq('status', 'Active').execute()
    if res.data:
        license_data = res.data[0]
        duration_days = license_data.get('duration_days', 30)
        
        supabase.table('sys_licenses').update({'status': 'Used', 'used_by': owner_id}).eq('id', license_data['id']).execute()
        return jsonify({'success': True, 'duration_days': duration_days})
        
    return jsonify({'success': False, 'message': 'Invalid or Expired Key'})

# New API to get opening balance for a customer for a specific month/year
@app.route('/api/opening_balance', methods=['GET'])
def get_opening_balance():
    cust_name = request.args.get('cust_name')
    company = request.args.get('company')
    
    try:
        month = int(request.args.get('month', 0))
        year = int(request.args.get('year', 0))
    except (TypeError, ValueError):
        return jsonify({"opening_balance": 0, "transactions": [], "error": "Invalid month or year parameters"}), 400

    # Fetch all transactions to avoid string comparison issues with dates
    transactions_res = supabase.table('sys_trans').select('*').eq('cust', cust_name).eq('company', company).neq('shift', 'General Bill').execute()
    transactions_all = transactions_res.data if transactions_res.data else []

    opening_balance = 0
    month_transactions = []

    for t in transactions_all:
        d_str = str(t.get('date', '')).strip()
        t_year, t_month = 0, 0
        try:
            # Standardize date parsing
            parts = re.split(r'[-/]', d_str)
            if len(parts) == 3:
                if len(parts[0]) == 4: # YYYY-MM-DD
                    t_year, t_month = int(parts[0]), int(parts[1])
                elif len(parts[2]) == 4: # DD-MM-YYYY
                    t_year, t_month = int(parts[2]), int(parts[1])
        except (ValueError, IndexError):
            continue
            
        if t_year > 0 and t_month > 0:
            if t_year < year or (t_year == year and t_month < month):
                if t['item'] == 'Payment':
                    opening_balance -= abs(float(t.get('total') or 0))
                else:
                    opening_balance += float(t.get('total') or 0)
            elif t_year == year and t_month == month:
                month_transactions.append(t)
    
    return jsonify({"opening_balance": opening_balance, "transactions": month_transactions})

if __name__ == '__main__':
    ensure_admin()
    print("Backend Chal Raha Hai... Browser Me Login Karein!")
    app.run(host='0.0.0.0', debug=True, port=5000)
