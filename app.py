import os
import re
import time
import hmac
import hashlib
import secrets
import sqlite3
import smtplib
from email.message import EmailMessage

from flask import Flask, request, redirect, session, render_template_string, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("Set SECRET_KEY in the environment before starting the app.")

DB = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "rewards.db"))
CODE_LIFETIME = 600
MAX_ATTEMPTS = 5

def setup():
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                country TEXT NOT NULL,
                points INTEGER NOT NULL DEFAULT 0
            )
        """)
        cols = {r[1] for r in con.execute("PRAGMA table_info(users)")}
        additions = {
            "email": "TEXT",
            "verified": "INTEGER NOT NULL DEFAULT 1",
            "code_hash": "TEXT",
            "code_expires": "INTEGER",
            "code_attempts": "INTEGER NOT NULL DEFAULT 0"
        }
        for name, definition in additions.items():
            if name not in cols:
                con.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
        con.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
            ON users(email) WHERE email IS NOT NULL AND email != ''
        """)

setup()

TEXT = {
    "ar": {
        "tag":"منصتك للمكافآت والألعاب",
        "create":"أنشئ حسابك",
        "sub":"ابدأ رحلتك مع Rewards",
        "user":"اسم المستخدم",
        "email":"بريد Gmail",
        "pass":"كلمة المرور",
        "country":"اختر بلدك",
        "register":"إنشاء حساب",
        "have":"عندك حساب بالفعل؟",
        "login":"تسجيل الدخول",
        "welcome":"أهلاً بك",
        "balance":"رصيدك",
        "points":"نقطة",
        "offers":"عروض الألعاب",
        "soon":"العروض هتكون متاحة بعد ربط شبكة عروض معتمدة.",
        "logout":"تسجيل الخروج",
        "back":"العودة لإنشاء حساب",
        "bad":"راجع البيانات وحاول مرة أخرى. كلمة المرور يجب أن تكون 8 أحرف على الأقل.",
        "exists":"البريد الإلكتروني مسجل بالفعل. جرّب تسجيل الدخول أو استعادة الوصول.",
        "taken":"البريد الإلكتروني أو كلمة المرور غير صحيحة، أو البريد لم يتم تفعيله.",
        "choose":"اختر اللغة",
        "footer":"العب. أكمل العروض. اجمع النقاط.",
        "verify":"تفعيل البريد الإلكتروني",
        "verify_sub":"اكتب الكود المكوّن من 6 أرقام الذي أرسلناه إلى بريدك.",
        "code":"كود التفعيل",
        "activate":"تفعيل الحساب",
        "resend":"إعادة إرسال الكود",
        "sent":"تم إرسال كود التفعيل إلى بريدك.",
        "expired":"الكود غير صحيح أو انتهت صلاحيته. يمكنك طلب كود جديد.",
        "active":"تم تفعيل بريدك بنجاح. يمكنك المتابعة الآن.",
        "send_error":"تعذّر إرسال البريد. تأكد من إعدادات Gmail ثم اطلب كودًا جديدًا.",
        "wait":"انتظر قليلًا قبل طلب كود آخر.",
        "resend_ok":"تم إرسال كود جديد.",
        "not_pending":"لا يوجد حساب ينتظر التفعيل في هذه الجلسة."
    },
    "en": {
        "tag":"Your rewards and gaming platform",
        "create":"Create your account",
        "sub":"Start your journey with Rewards",
        "user":"Username",
        "email":"Gmail address",
        "pass":"Password",
        "country":"Choose your country",
        "register":"Create account",
        "have":"Already have an account?",
        "login":"Log in",
        "welcome":"Welcome",
        "balance":"Your balance",
        "points":"points",
        "offers":"Game offers",
        "soon":"Offers will appear after an approved offerwall is connected.",
        "logout":"Log out",
        "back":"Back to registration",
        "bad":"Check your details. Password must be at least 8 characters.",
        "exists":"This email is already registered. Please log in instead.",
        "taken":"Incorrect email or password, or the email is not verified.",
        "choose":"Choose language",
        "footer":"Play. Complete offers. Earn points.",
        "verify":"Verify your email",
        "verify_sub":"Enter the 6-digit code sent to your email.",
        "code":"Verification code",
        "activate":"Verify account",
        "resend":"Resend code",
        "sent":"A verification code was sent to your email.",
        "expired":"Invalid or expired code. You can request a new one.",
        "active":"Your email is verified successfully.",
        "send_error":"Email could not be sent. Check Gmail settings and request a new code.",
        "wait":"Please wait before requesting another code.",
        "resend_ok":"A new code was sent.",
        "not_pending":"No account is awaiting verification in this session."
    }
}

def lang():
    value = session.get("lang", "ar")
    return value if value in TEXT else "ar"

def send_code(to_email, code, language=None):
    sender = os.environ.get("MAIL_ADDRESS", "").strip()
    password = os.environ.get("MAIL_APP_PASSWORD", "").replace(" ", "").strip()
    if not sender or not password:
        raise RuntimeError("Email environment variables are missing")

    language = language or lang()
    msg = EmailMessage()
    msg["Subject"] = (
        "كود تفعيل حساب Rewards"
        if language == "ar"
        else "Your Rewards verification code"
    )
    msg["From"] = sender
    msg["To"] = to_email

    if language == "ar":
        body = (
            f"كود تفعيل حسابك في Rewards هو: {code}\\n\\n"
            "الكود صالح لمدة 10 دقائق. إذا لم تطلب هذا الكود، يمكنك تجاهل الرسالة."
        )
    else:
        body = (
            f"Your Rewards verification code is: {code}\\n\\n"
            "This code expires in 10 minutes. If you did not request it, ignore this email."
        )
    msg.set_content(body)

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=25) as server:
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)

def page(title, content, msg=""):
    language = lang()
    t = TEXT[language]
    direction = "rtl" if language == "ar" else "ltr"
    return render_template_string("""
    <!doctype html>
    <html lang="{{ language }}" dir="{{ direction }}">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{{ title }} | Rewards</title>
      <style>
      *{box-sizing:border-box}
      body{margin:0;background:#0b1220;color:#f8fafc;font-family:Arial,sans-serif;min-height:100vh}
      header{height:76px;display:flex;align-items:center;justify-content:space-between;padding:0 6%;border-bottom:1px solid #253047;background:#101a2c}
      .logo{font-size:23px;font-weight:800;color:#52e0b0}
      select,input,button{font:inherit}
      .language{background:#1c2940;color:white;border:1px solid #34425a;border-radius:9px;padding:10px}
      main{width:100%;max-width:470px;margin:45px auto;padding:0 18px}
      .card{background:#131f33;border:1px solid #27364f;border-radius:20px;padding:28px 24px;box-shadow:0 16px 50px #0003}
      .icon{width:54px;height:54px;border-radius:16px;background:#183d3a;display:grid;place-items:center;font-size:27px;margin-bottom:20px}
      h1{font-size:27px;margin:0 0 10px}
      .sub{color:#9eacc2;line-height:1.7;margin:0 0 25px}
      label{display:block;font-size:14px;color:#d9e2ef;margin:14px 0 8px}
      input,.country{width:100%;padding:14px;background:#0d1728;color:white;border:1px solid #33425b;border-radius:10px;outline:none}
      input:focus,select:focus{border-color:#52e0b0}
      button{width:100%;border:0;border-radius:10px;padding:14px;margin-top:20px;background:#52e0b0;color:#092018;font-weight:800;cursor:pointer}
      .switch{text-align:center;color:#aab7ca;margin:22px 0 0;font-size:14px;line-height:1.8}
      a{color:#52e0b0;text-decoration:none;font-weight:bold}
      .message{padding:12px;background:#43262d;border-radius:9px;color:#ffd2d8;margin-bottom:16px}
      .balance{font-size:30px;font-weight:800;color:#52e0b0;margin:15px 0}
      .muted{color:#aab7ca;line-height:1.8}
      footer{text-align:center;color:#7f8da5;padding:20px;font-size:13px}
      @media(max-width:480px){main{margin:28px auto}.card{padding:23px 19px}h1{font-size:24px}}
      </style>
    </head>
    <body>
      <header>
        <div class="logo">◈ Rewards</div>
        <form action="/language" method="post">
          <select class="language" name="language" onchange="this.form.submit()"
          aria-label="{{ t['choose'] }}">
            <option value="ar" {% if language=='ar' %}selected{% endif %}>العربية</option>
            <option value="en" {% if language=='en' %}selected{% endif %}>English</option>
          </select>
        </form>
      </header>
      <main><section class="card">
        {{ content|safe }}
        {% if msg %}<div class="message">{{ msg }}</div>{% endif %}
      </section></main>
      <footer>{{ t['footer'] }}</footer>
    </body>
    </html>
    """, title=title, content=content, msg=msg,
       language=language, direction=direction, t=t)

@app.post("/language")
def language():
    value = request.form.get("language", "ar")
    session["lang"] = value if value in TEXT else "ar"
    return redirect(request.referrer or "/")

@app.get("/")
def home():
    if session.get("uid"):
        return redirect("/dashboard")
    if session.get("pending_uid"):
        return redirect("/verify")
    return redirect("/register")

@app.route("/register", methods=["GET", "POST"])
def register():
    t = TEXT[lang()]
    msg = ""

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        country = request.form.get("country", "")
        allowed = {"EG", "US", "SA", "AE", "MA", "DZ", "TN", "JO", "KW", "QA"}

        if (len(password) < 8 or country not in allowed
                or not re.fullmatch(r"[A-Za-z0-9._%+-]+@gmail\.com", email, re.I)):
            msg = t["bad"]
        else:
            now = int(time.time())
            code = f"{secrets.randbelow(1000000):06d}"
            code_hash = generate_password_hash(code)
            language = lang()

            try:
                with sqlite3.connect(DB) as con:
                    existing = con.execute(
                        "SELECT id, verified FROM users WHERE lower(email)=?",
                        (email,)
                    ).fetchone()

                    if existing and existing[1]:
                        msg = t["exists"]
                    elif existing:
                        user_id = existing[0]
                        con.execute(
                            """UPDATE users
                               SET password=?, country=?, code_hash=?, code_expires=?,
                                   code_attempts=0
                               WHERE id=?""",
                            (generate_password_hash(password), country, code_hash,
                             now + CODE_LIFETIME, user_id)
                        )
                    else:
                        internal_username = "email_" + secrets.token_hex(12)
                        cur = con.execute(
                            """INSERT INTO users
                               (username,password,country,email,verified,code_hash,code_expires,code_attempts)
                               VALUES(?,?,?,?,0,?,?,0)""",
                            (internal_username, generate_password_hash(password),
                             country, email, code_hash, now + CODE_LIFETIME)
                        )
                        user_id = cur.lastrowid

                if not msg:
                    session.clear()
                    session["lang"] = language
                    session["pending_uid"] = user_id
                    session["last_code_sent"] = now - 60
                    try:
                        send_code(email, code, language)
                        session["last_code_sent"] = now
                        return redirect("/verify?sent=1")
                    except Exception:
                        app.logger.exception("Verification email could not be sent")
                        return redirect("/verify?send_error=1")

            except sqlite3.IntegrityError:
                msg = t["exists"]

    content = """
    <div class="icon">🎮</div>
    <h1>""" + t["create"] + """</h1>
    <p class="sub">""" + t["sub"] + """</p>
    <form method="post">
      <label>""" + t["email"] + """</label>
      <input name="email" type="email" required autocomplete="email"
             placeholder="you@gmail.com"
             pattern="[A-Za-z0-9._%+-]+@gmail\\.com">
      <label>""" + t["pass"] + """</label>
      <input name="password" type="password" required minlength="8"
             autocomplete="new-password">
      <label>""" + t["country"] + """</label>
      <select class="country" name="country" required>
        <option value="EG">🇪🇬 Egypt / مصر</option>
        <option value="US">🇺🇸 United States</option>
        <option value="SA">🇸🇦 Saudi Arabia / السعودية</option>
        <option value="AE">🇦🇪 United Arab Emirates</option>
        <option value="MA">🇲🇦 Morocco / المغرب</option>
        <option value="DZ">🇩🇿 Algeria / الجزائر</option>
        <option value="TN">🇹🇳 Tunisia / تونس</option>
        <option value="JO">🇯🇴 Jordan / الأردن</option>
        <option value="KW">🇰🇼 Kuwait / الكويت</option>
        <option value="QA">🇶🇦 Qatar / قطر</option>
      </select>
      <button type="submit">""" + t["register"] + """</button>
    </form>
    <p class="switch">""" + t["have"] + """<br><a href="/login">""" + t["login"] + """</a></p>
    """
    return page(t["create"], content, msg)

@app.route("/verify", methods=["GET", "POST"])
def verify():
    t = TEXT[lang()]
    user_id = session.get("pending_uid")
    msg = ""
    if not user_id:
        return page(t["verify"], "<h1>"+t["verify"]+"</h1><p>"+t["not_pending"]+"</p><p><a href='/register'>"+t["back"]+"</a></p>")

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        with sqlite3.connect(DB) as con:
            row = con.execute(
                "SELECT verified,code_hash,code_expires,code_attempts FROM users WHERE id=?",
                (user_id,)).fetchone()

            if not row or row[0]:
                session.pop("pending_uid", None)
                return redirect("/login")

            if row[3] >= MAX_ATTEMPTS:
                msg = t["expired"]
            elif not row[1] or not row[2] or int(time.time()) > row[2]:
                msg = t["expired"]
            elif not re.fullmatch(r"\d{6}", code) or not check_password_hash(row[1], code):
                con.execute("UPDATE users SET code_attempts=code_attempts+1 WHERE id=?", (user_id,))
                msg = t["expired"]
            else:
                con.execute(
                    "UPDATE users SET verified=1,code_hash=NULL,code_expires=NULL,code_attempts=0 WHERE id=?",
                    (user_id,))
                language = lang()
                session.clear()
                session["lang"] = language
                session["uid"] = user_id
                return redirect("/dashboard")

    if request.args.get("send_error"):
        msg = t["send_error"]
    elif request.args.get("sent"):
        msg = t["sent"]

    content = """
    <div class="icon">📧</div>
    <h1>"""+t["verify"]+"""</h1>
    <p class="sub">"""+t["verify_sub"]+"""</p>
    <form method="post">
      <label>"""+t["code"]+"""</label>
      <input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code">
      <button type="submit">"""+t["activate"]+"""</button>
    </form>
    <form method="post" action="/resend">
      <button type="submit">"""+t["resend"]+"""</button>
    </form>
    """
    return page(t["verify"], content, msg)

@app.post("/resend")
def resend():
    t = TEXT[lang()]
    user_id = session.get("pending_uid")
    if not user_id:
        return redirect("/register")

    now = int(time.time())
    last = int(session.get("last_code_sent", 0))
    if now - last < 60:
        return page(t["verify"], "<h1>"+t["verify"]+"</h1><p><a href='/verify'>"+t["verify"]+"</a></p>", t["wait"])

    with sqlite3.connect(DB) as con:
        row = con.execute("SELECT email,verified FROM users WHERE id=?", (user_id,)).fetchone()
        if not row or row[1]:
            session.pop("pending_uid", None)
            return redirect("/login")
        email = row[0]
        code = f"{secrets.randbelow(1000000):06d}"
        con.execute(
            "UPDATE users SET code_hash=?,code_expires=?,code_attempts=0 WHERE id=?",
            (generate_password_hash(code), now + CODE_LIFETIME, user_id))

    try:
        send_code(email, code, lang())
        session["last_code_sent"] = now
        return redirect("/verify?sent=1")
    except Exception:
        app.logger.exception("Resending verification email failed")
        return redirect("/verify?send_error=1")

@app.route("/login", methods=["GET", "POST"])
def login():
    t = TEXT[lang()]
    msg = t["active"] if request.args.get("verified") else ""

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with sqlite3.connect(DB) as con:
            row = con.execute(
                "SELECT id,password,verified FROM users WHERE lower(email)=?",
                (email,)
            ).fetchone()

        if row and check_password_hash(row[1], password):
            language = lang()
            if not row[2]:
                session.clear()
                session["lang"] = language
                session["pending_uid"] = row[0]
                return redirect("/verify")

            session.clear()
            session["lang"] = language
            session["uid"] = row[0]
            return redirect("/dashboard")

        msg = t["taken"]

    content = """
    <div class="icon">🔐</div>
    <h1>""" + t["login"] + """</h1>
    <p class="sub">""" + t["sub"] + """</p>
    <form method="post">
      <label>""" + t["email"] + """</label>
      <input name="email" type="email" required autocomplete="email"
             placeholder="you@gmail.com">
      <label>""" + t["pass"] + """</label>
      <input name="password" type="password" required autocomplete="current-password">
      <button type="submit">""" + t["login"] + """</button>
    </form>
    <p class="switch"><a href="/register">""" + t["back"] + """</a></p>
    """
    return page(t["login"], content, msg)

@app.get("/dashboard")
def dashboard():
    if not session.get("uid"):
        return redirect("/login")

    t = TEXT[lang()]
    with sqlite3.connect(DB) as con:
        user = con.execute(
            "SELECT username,country,points,verified FROM users WHERE id=?",
            (session["uid"],)
        ).fetchone()

    if not user or not user[3]:
        session.clear()
        return redirect("/login")

    content = """
    <div style="text-align:center">
      <div class="icon">👋</div>
      <h1>أهلاً بك في موقع المكافآت</h1>
      <p class="sub">""" + str(user[0]) + """</p>
      <p class="muted">رصيدك الحالي</p>
      <div class="balance">""" + str(user[2]) + """ نقطة</div>
    </div>

    <div style="display:grid;gap:12px;margin-top:25px">
      <a href="/offers" style="display:block;padding:17px;border-radius:14px;background:#e8f5e9;color:#176b35;text-decoration:none;font-weight:bold">
        🎮 عروض الألعاب
        <div style="font-size:13px;font-weight:normal;margin-top:6px">تصفّح العروض المتاحة واجمع النقاط</div>
      </a>

      <a href="/withdraw" style="display:block;padding:17px;border-radius:14px;background:#e8f0ff;color:#174ea6;text-decoration:none;font-weight:bold">
        💰 طلب سحب
        <div style="font-size:13px;font-weight:normal;margin-top:6px">قدّم طلب سحب وتابع حالته</div>
      </a>

      <a href="/admin" style="display:block;padding:17px;border-radius:14px;background:#f3e8ff;color:#6b21a8;text-decoration:none;font-weight:bold">
        ⚙️ لوحة الإدارة
        <div style="font-size:13px;font-weight:normal;margin-top:6px">إدارة العروض والنقاط وطلبات السحب</div>
      </a>
    </div>

    <p class="muted" style="text-align:center;margin-top:20px">
      ملحوظة: توفر العروض والسحب الفعلي يعتمد على ربط خدمات خارجية موثوقة.
    </p>
    <p class="switch"><a href="/logout">تسجيل الخروج</a></p>
    """
    return page("لوحة التحكم", content)

@app.get("/logout")
def logout():
    session.clear()
    return redirect("/register")


# ===== Rewards, withdrawals and admin =====

def ensure_reward_tables():
    with sqlite3.connect(DB) as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS offers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            reward_points INTEGER NOT NULL DEFAULT 0,
            target_url TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS withdrawals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            points INTEGER NOT NULL,
            method TEXT NOT NULL,
            payment_details TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS point_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            points INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)

ensure_reward_tables()

@app.get("/offers")
def rewards_offers():
    if not session.get("uid"):
        return redirect("/login")
    with sqlite3.connect(DB) as con:
        offers = con.execute(
            "SELECT id,title,description,reward_points,target_url "
            "FROM offers WHERE active=1 ORDER BY id DESC"
        ).fetchall()
    items = "".join(
        "<article><h3>" + str(o[1]) + "</h3><p>" + str(o[2]) +
        "</p><p>المكافأة: " + str(o[3]) +
        " نقطة</p>" +
        ('<p><a href="' + str(o[4]) + '" target="_blank" rel="noopener">فتح العرض</a></p>'
         if o[4].startswith("https://") else "") +
        "</article>" for o in offers
    ) or "<p>لا توجد عروض متاحة حاليًا.</p>"
    content = (
        "<h1>عروض الألعاب</h1>" + items +
        '<p><a href="/dashboard">العودة للوحة التحكم</a></p>'
    )
    return page("عروض الألعاب", content)

@app.route("/withdraw", methods=["GET", "POST"])
def rewards_withdraw():
    if not session.get("uid"):
        return redirect("/login")
    msg = ""
    if request.method == "POST":
        try:
            points = int(request.form.get("points", "0"))
        except ValueError:
            points = 0
        method = request.form.get("method", "").strip()[:40]
        details = request.form.get("details", "").strip()[:300]
        if points <= 0 or not method or not details:
            msg = "راجع المبلغ وطريقة السحب وبيانات الدفع."
        else:
            with sqlite3.connect(DB) as con:
                con.execute("BEGIN IMMEDIATE")
                row = con.execute(
                    "SELECT points FROM users WHERE id=? AND verified=1",
                    (session["uid"],)
                ).fetchone()
                if not row or row[0] < points:
                    msg = "رصيد النقاط غير كافٍ."
                else:
                    con.execute(
                        "UPDATE users SET points=points-? WHERE id=?",
                        (points, session["uid"])
                    )
                    cur = con.execute(
                        "INSERT INTO withdrawals "
                        "(user_id,points,method,payment_details,status,created_at) "
                        "VALUES (?,?,?,?, 'pending', ?)",
                        (session["uid"], points, method, details, int(time.time()))
                    )
                    con.execute(
                        "INSERT INTO point_transactions "
                        "(user_id,points,reason,created_at) VALUES (?,?,?,?)",
                        (session["uid"], -points, "طلب سحب", int(time.time()))
                    )
                    msg = "تم تسجيل طلب السحب للمراجعة. رقم الطلب: " + str(cur.lastrowid)
    with sqlite3.connect(DB) as con:
        balance = con.execute(
            "SELECT points FROM users WHERE id=?", (session["uid"],)
        ).fetchone()
        requests_list = con.execute(
            "SELECT id,points,method,status FROM withdrawals "
            "WHERE user_id=? ORDER BY id DESC LIMIT 20",
            (session["uid"],)
        ).fetchall()
    rows = "".join(
        "<li>طلب #" + str(r[0]) + " — " + str(r[1]) + " نقطة — " +
        str(r[2]) + " — " + str(r[3]) + "</li>" for r in requests_list
    ) or "<li>لا توجد طلبات سحب.</li>"
    content = (
        "<h1>طلب سحب</h1><p>رصيدك: " + str(balance[0] if balance else 0) +
        " نقطة</p><p>" + msg + "</p>"
        '<form method="post"><label>عدد النقاط</label>'
        '<input type="number" name="points" min="1" required>'
        '<label>طريقة السحب</label>'
        '<input name="method" maxlength="40" placeholder="وسيلة الدفع" required>'
        '<label>بيانات الاستلام</label>'
        '<input name="details" maxlength="300" required>'
        '<button type="submit">إرسال الطلب</button></form>'
        "<h3>طلباتي</h3><ul>" + rows + "</ul>"
        '<p><a href="/dashboard">العودة للوحة التحكم</a></p>'
    )
    return page("طلب سحب", content)

@app.route("/admin", methods=["GET", "POST"])
def rewards_admin():
    if not session.get("is_admin"):
        if request.method == "POST":
            supplied = request.form.get("admin_password", "")
            expected = os.environ.get("ADMIN_PASSWORD", "")
            if expected and hmac.compare_digest(supplied, expected):
                session["is_admin"] = True
                return redirect("/admin")
        content = (
            "<h1>دخول الأدمن</h1>"
            '<form method="post"><label>كلمة مرور الأدمن</label>'
            '<input type="password" name="admin_password" required>'
            '<button type="submit">دخول</button></form>'
            "<p>يلزم ضبط ADMIN_PASSWORD في بيئة التشغيل أولًا.</p>"
        )
        return page("دخول الأدمن", content)

    msg = ""
    if request.method == "POST":
        action = request.form.get("action", "")
        with sqlite3.connect(DB) as con:
            con.execute("BEGIN IMMEDIATE")
            if action == "add_offer":
                title = request.form.get("title", "").strip()[:100]
                description = request.form.get("description", "").strip()[:500]
                url = request.form.get("url", "").strip()[:500]
                try:
                    reward = int(request.form.get("reward", "0"))
                except ValueError:
                    reward = 0
                if title and reward >= 0 and (not url or url.startswith("https://")):
                    con.execute(
                        "INSERT INTO offers(title,description,reward_points,target_url,created_at) "
                        "VALUES(?,?,?,?,?)",
                        (title, description, reward, url, int(time.time()))
                    )
                    msg = "تمت إضافة العرض. النقاط لا تُمنح تلقائيًا قبل التحقق من إكمال المهمة."
                else:
                    msg = "راجع بيانات العرض والرابط الآمن."
            elif action in ("approve", "reject"):
                try:
                    wid = int(request.form.get("withdrawal_id", "0"))
                except ValueError:
                    wid = 0
                row = con.execute(
                    "SELECT user_id,points,status FROM withdrawals WHERE id=?", (wid,)
                ).fetchone()
                if row and row[2] == "pending":
                    if action == "approve":
                        con.execute(
                            "UPDATE withdrawals SET status='approved' WHERE id=?", (wid,)
                        )
                        msg = "تم اعتماد الطلب. يلزم تنفيذ الدفع يدويًا."
                    else:
                        con.execute(
                            "UPDATE withdrawals SET status='rejected' WHERE id=?", (wid,)
                        )
                        con.execute(
                            "UPDATE users SET points=points+? WHERE id=?", (row[1], row[0])
                        )
                        con.execute(
                            "INSERT INTO point_transactions(user_id,points,reason,created_at) "
                            "VALUES(?,?,?,?)",
                            (row[0], row[1], "إرجاع نقاط لرفض طلب السحب", int(time.time()))
                        )
                        msg = "تم رفض الطلب وإرجاع النقاط."
                else:
                    msg = "الطلب غير موجود أو تمت مراجعته من قبل."
            elif action == "credit":
                try:
                    uid = int(request.form.get("user_id", "0"))
                    pts = int(request.form.get("points", "0"))
                except ValueError:
                    uid, pts = 0, 0
                reason = request.form.get("reason", "").strip()[:200]
                exists = con.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone()
                if exists and pts > 0 and reason:
                    con.execute("UPDATE users SET points=points+? WHERE id=?", (pts, uid))
                    con.execute(
                        "INSERT INTO point_transactions(user_id,points,reason,created_at) "
                        "VALUES(?,?,?,?)", (uid, pts, reason, int(time.time()))
                    )
                    msg = "تمت إضافة النقاط وتسجيل سببها."
                else:
                    msg = "راجع رقم المستخدم وعدد النقاط والسبب."
    with sqlite3.connect(DB) as con:
        offers = con.execute(
            "SELECT id,title,reward_points,active FROM offers ORDER BY id DESC"
        ).fetchall()
        withdrawals = con.execute(
            "SELECT w.id,w.user_id,u.email,w.points,w.method,w.payment_details,w.status "
            "FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC LIMIT 100"
        ).fetchall()
        users = con.execute("SELECT id,email,points FROM users ORDER BY id DESC").fetchall()

    offer_rows = "".join(
        "<li>#" + str(o[0]) + " " + str(o[1]) + " — " +
        str(o[2]) + " نقطة — نشط: " + str(o[3]) + "</li>" for o in offers
    ) or "<li>لا توجد عروض.</li>"
    withdrawal_rows = "".join(
        "<li>طلب #" + str(w[0]) + " — المستخدم #" + str(w[1]) +
        " — " + str(w[2] or "") + " — " + str(w[3]) + " نقطة — " +
        str(w[4]) + " — بيانات الاستلام: " + str(w[5]) +
        " — الحالة: " + str(w[6]) +
        (('<form method="post"><input type="hidden" name="withdrawal_id" value="' +
          str(w[0]) + '"><button name="action" value="approve">اعتماد</button>'
          '<button name="action" value="reject">رفض وإرجاع النقاط</button></form>')
         if w[6] == "pending" else "") + "</li>" for w in withdrawals
    ) or "<li>لا توجد طلبات سحب.</li>"
    user_rows = "".join(
        "<li>#" + str(u[0]) + " — " + str(u[1] or "") +
        " — الرصيد: " + str(u[2]) + "</li>" for u in users
    ) or "<li>لا يوجد مستخدمون.</li>"
    content = (
        "<h1>لوحة الأدمن</h1><p>" + msg + "</p>"
        '<h2>إضافة عرض</h2><form method="post">'
        '<input type="hidden" name="action" value="add_offer">'
        '<label>عنوان العرض</label><input name="title" required maxlength="100">'
        '<label>الوصف</label><input name="description" maxlength="500">'
        '<label>رابط العرض (HTTPS)</label><input name="url" type="url">'
        '<label>النقاط المعلنة</label><input name="reward" type="number" min="0" required>'
        '<button type="submit">إضافة العرض</button></form>'
        '<h2>إضافة نقاط يدويًا</h2><form method="post">'
        '<input type="hidden" name="action" value="credit">'
        '<label>رقم المستخدم</label><input name="user_id" type="number" min="1" required>'
        '<label>النقاط</label><input name="points" type="number" min="1" required>'
        '<label>السبب</label><input name="reason" required maxlength="200">'
        '<button type="submit">إضافة النقاط</button></form>'
        "<h2>المستخدمون</h2><ul>" + user_rows + "</ul>"
        "<h2>العروض</h2><ul>" + offer_rows + "</ul>"
        "<h2>طلبات السحب</h2><ul>" + withdrawal_rows + "</ul>"
        '<form method="post" action="/admin/logout"><button>تسجيل خروج الأدمن</button></form>'
    )
    return page("لوحة الأدمن", content)

@app.post("/admin/logout")
def rewards_admin_logout():
    session.pop("is_admin", None)
    return redirect("/admin")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
