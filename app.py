import hashlib
import socket
import json
import secrets
import sqlite3
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "neighbor_aid.db"
STATIC = ROOT / "static"


def now():
    return int(time.time())


def hash_password(password: str, salt: str | None = None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return salt, digest


def verify_password(password, salt, digest):
    return hash_password(password, salt)[1] == digest


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'resident',
            password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, points INTEGER NOT NULL DEFAULT 120,
            rating REAL NOT NULL DEFAULT 5.0, verified INTEGER NOT NULL DEFAULT 0,
            real_name TEXT, id_card_last4 TEXT, verification_status TEXT NOT NULL DEFAULT '未认证',
            community TEXT, building TEXT, unit TEXT, resident_type TEXT,
            community_status TEXT NOT NULL DEFAULT '未加入', tutorial_completed INTEGER NOT NULL DEFAULT 0,
            rules_accepted INTEGER NOT NULL DEFAULT 0, skills TEXT, privacy_building INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL,
            category TEXT NOT NULL, urgency TEXT NOT NULL DEFAULT '普通', area TEXT NOT NULL,
            scheduled_time TEXT NOT NULL, reward INTEGER NOT NULL DEFAULT 10, status TEXT NOT NULL DEFAULT '待接单',
            owner_id INTEGER NOT NULL, helper_id INTEGER, photo TEXT, completion_photo TEXT, created_at INTEGER NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id), FOREIGN KEY(helper_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS task_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, actor_id INTEGER NOT NULL,
            event_type TEXT NOT NULL, note TEXT, created_at INTEGER NOT NULL,
            FOREIGN KEY(task_id) REFERENCES tasks(id), FOREIGN KEY(actor_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, reviewer_id INTEGER NOT NULL,
            reviewee_id INTEGER NOT NULL, rating INTEGER NOT NULL, comment TEXT NOT NULL, created_at INTEGER NOT NULL,
            UNIQUE(task_id, reviewer_id), FOREIGN KEY(task_id) REFERENCES tasks(id),
            FOREIGN KEY(reviewer_id) REFERENCES users(id), FOREIGN KEY(reviewee_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS points_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, amount INTEGER NOT NULL,
            reason TEXT NOT NULL, task_id INTEGER, created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(task_id) REFERENCES tasks(id)
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL,
            body TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL, body TEXT NOT NULL, read INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
            FOREIGN KEY(task_id) REFERENCES tasks(id), FOREIGN KEY(sender_id) REFERENCES users(id), FOREIGN KEY(receiver_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS rewards (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL,
            points INTEGER NOT NULL, stock INTEGER NOT NULL DEFAULT 0, season TEXT NOT NULL,
            pickup_place TEXT NOT NULL DEFAULT '幸福里社区服务站', pickup_time TEXT NOT NULL DEFAULT '工作日 09:00-17:00', materials TEXT NOT NULL DEFAULT '身份证原件、兑换记录'
        );
        CREATE TABLE IF NOT EXISTS redemptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, reward_id INTEGER NOT NULL,
            points INTEGER NOT NULL, status TEXT NOT NULL DEFAULT '待领取', created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(reward_id) REFERENCES rewards(id)
        );
        """
    )
    task_columns = {r["name"] for r in conn.execute("PRAGMA table_info(tasks)").fetchall()}
    if "photo" not in task_columns: conn.execute("ALTER TABLE tasks ADD COLUMN photo TEXT")
    if "completion_photo" not in task_columns: conn.execute("ALTER TABLE tasks ADD COLUMN completion_photo TEXT")
    user_columns = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "real_name" not in user_columns: conn.execute("ALTER TABLE users ADD COLUMN real_name TEXT")
    if "id_card_last4" not in user_columns: conn.execute("ALTER TABLE users ADD COLUMN id_card_last4 TEXT")
    if "verification_status" not in user_columns: conn.execute("ALTER TABLE users ADD COLUMN verification_status TEXT NOT NULL DEFAULT '未认证'")
    for name, definition in [("community","TEXT"),("building","TEXT"),("unit","TEXT"),("resident_type","TEXT"),("community_status","TEXT NOT NULL DEFAULT '未加入'"),("tutorial_completed","INTEGER NOT NULL DEFAULT 0"),("rules_accepted","INTEGER NOT NULL DEFAULT 0"),("skills","TEXT"),("privacy_building","INTEGER NOT NULL DEFAULT 0")]:
        if name not in user_columns: conn.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        salt, digest = hash_password("123456")
        conn.execute("INSERT INTO users(phone,name,role,password_hash,password_salt,points,verified,verification_status,created_at) VALUES(?,?,?,?,?,?,?,?,?)", ("13800138000", "周小邻", "resident", digest, salt, 186, 1, "已认证", now()))
        helper_salt, helper_digest = hash_password("123456")
        conn.execute("INSERT INTO users(phone,name,role,password_hash,password_salt,points,verified,verification_status,created_at) VALUES(?,?,?,?,?,?,?,?,?)", ("13900139000", "林志愿", "volunteer", helper_digest, helper_salt, 328, 1, "已认证", now()))
        admin_salt, admin_digest = hash_password("admin123")
        conn.execute("INSERT INTO users(phone,name,role,password_hash,password_salt,points,verified,verification_status,created_at) VALUES(?,?,?,?,?,?,?,?,?)", ("15000150000", "社区管理员", "admin", admin_digest, admin_salt, 999, 1, "已认证", now()))
        owner = conn.execute("SELECT id FROM users WHERE phone='13800138000'").fetchone()[0]
        conn.execute("INSERT INTO tasks(title,description,category,urgency,area,scheduled_time,reward,status,owner_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", ("帮忙取一趟社区药品", "独居老人需要到社区卫生服务站取药，药品已付款，步行约 8 分钟。", "跑腿代办", "紧急", "幸福里社区", "今天 17:30", 30, "待接单", owner, now()))
        conn.execute("INSERT INTO tasks(title,description,category,urgency,area,scheduled_time,reward,status,owner_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", ("周末帮忙照看猫咪", "周六上午到家里添粮换水，猫咪很亲人，离开前拍照反馈即可。", "宠物照看", "普通", "城市新苑", "本周六 09:00", 50, "待接单", owner, now()))
        conn.execute("INSERT INTO tasks(title,description,category,urgency,area,scheduled_time,reward,status,owner_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", ("更换厨房水龙头", "新配件已经准备好，希望有经验的邻居帮忙更换。", "家居维修", "普通", "阳光花园", "明天 18:30", 40, "待接单", owner, now()))
    if conn.execute("SELECT COUNT(*) FROM rewards").fetchone()[0] == 0:
        conn.executemany("INSERT INTO rewards(name,description,points,stock,season,pickup_place,pickup_time,materials) VALUES(?,?,?,?,?,?,?,?)", [("实用保温水壶", "适合春节、重阳等节日兑换", 120, 30, "节日礼遇", "幸福里社区服务站", "工作日 09:00-17:00", "身份证原件、兑换记录"), ("家用吹风机", "轻巧好用的生活小家电", 220, 20, "节日礼遇", "幸福里社区服务站", "工作日 09:00-17:00", "身份证原件、兑换记录"), ("迷你空气炸锅", "健康厨房人气礼品", 680, 8, "中秋礼遇", "幸福里社区服务站", "中秋活动周 09:00-18:00", "身份证原件、兑换记录"), ("多功能烤箱", "给热爱生活的邻居一份惊喜", 980, 5, "春节礼遇", "幸福里社区服务站", "春节前一周 09:00-18:00", "身份证原件、兑换记录、兑换短信")])
    reward_columns = {r["name"] for r in conn.execute("PRAGMA table_info(rewards)").fetchall()}
    for name, definition in [("pickup_place", "TEXT NOT NULL DEFAULT '幸福里社区服务站'"), ("pickup_time", "TEXT NOT NULL DEFAULT '工作日 09:00-17:00'"), ("materials", "TEXT NOT NULL DEFAULT '身份证原件、兑换记录'")]:
        if name not in reward_columns: conn.execute(f"ALTER TABLE rewards ADD COLUMN {name} {definition}")
        conn.execute("UPDATE users SET community='幸福里社区',building='1号楼',unit='1单元',resident_type='业主',community_status='已通过',tutorial_completed=1,rules_accepted=1 WHERE phone IN ('13800138000','13900139000','15000150000')")
    conn.commit()
    conn.close()


def row_dict(row):
    return dict(row) if row else None


def user_public(row):
    data = row_dict(row)
    if not data:
        return None
    data.pop("password_hash", None); data.pop("password_salt", None)
    return data


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        return

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers(); self.wfile.write(body)

    def parse_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def auth(self, required=True):
        token = self.headers.get("Authorization", "").replace("Bearer ", "").strip()
        conn = db(); row = conn.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>?", (token, now())).fetchone(); conn.close()
        if required and not row:
            self.send_json({"error": "请先登录"}, 401); return None
        return row

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            return self.serve_file(STATIC / "index.html", "text/html; charset=utf-8")
        if path.startswith("/static/"):
            file = STATIC / path.removeprefix("/static/")
            return self.serve_file(file, "text/css; charset=utf-8" if file.suffix == ".css" else "application/javascript; charset=utf-8")
        if path == "/api/me":
            user = self.auth(False); return self.send_json({"user": user_public(user)})
        if path == "/api/tasks": return self.tasks()
        if path.startswith("/api/tasks/") and path.endswith("/messages"): return self.messages(int(path.split("/")[3]))
        if path.startswith("/api/tasks/") and path.endswith("/detail"): return self.task_detail(int(path.split("/")[3]))
        if path == "/api/rewards": return self.rewards()
        if path == "/api/redemptions": return self.redemptions()
        if path == "/api/stats": return self.stats()
        if path == "/api/notifications": return self.notifications()
        if path == "/api/points": return self.points()
        self.send_json({"error": "接口不存在"}, 404)

    def serve_file(self, file, content_type):
        if not file.exists(): return self.send_json({"error": "资源不存在"}, 404)
        body = file.read_bytes(); self.close_connection = True; self.send_response(200); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(body))); self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/login": return self.login()
            if path == "/api/register": return self.register()
            user = self.auth()
            if not user: return
            if path == "/api/tasks": return self.create_task(user)
            if path == "/api/emergency": return self.create_emergency(user)
            if path == "/api/verify": return self.verify_identity(user)
            if path == "/api/admission": return self.admission(user)
            if path == "/api/tutorial/complete": return self.complete_tutorial(user)
            if path.startswith("/api/rewards/") and path.endswith("/redeem"): return self.redeem(user, int(path.split("/")[3]))
            if path.startswith("/api/tasks/") and path.endswith("/accept"): return self.accept_task(user, int(path.split("/")[3]))
            if path.startswith("/api/tasks/") and path.endswith("/status"): return self.update_task(user, int(path.split("/")[3]))
            if path.startswith("/api/tasks/") and path.endswith("/review"): return self.review(user, int(path.split("/")[3]))
            if path.startswith("/api/tasks/") and path.endswith("/messages"): return self.send_message(user, int(path.split("/")[3]))
            if path.startswith("/api/notifications/") and path.endswith("/read"): return self.mark_notification(user, int(path.split("/")[3]))
            if path == "/api/logout": return self.logout()
            self.send_json({"error": "接口不存在"}, 404)
        except (ValueError, KeyError, sqlite3.IntegrityError) as exc:
            self.send_json({"error": str(exc) or "请求参数无效"}, 400)

    def login(self):
        data = self.parse_body(); phone = str(data.get("phone", "")).strip(); password = str(data.get("password", "")); conn = db(); row = conn.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
        if not row or not verify_password(password, row["password_salt"], row["password_hash"]): conn.close(); return self.send_json({"error": "手机号或密码不正确"}, 401)
        token = secrets.token_urlsafe(32); conn.execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)", (token, row["id"], now()+60*60*24*7)); conn.commit(); conn.close(); self.send_json({"token": token, "user": user_public(row)})

    def register(self):
        data = self.parse_body(); phone = str(data.get("phone", "")).strip(); name = str(data.get("name", "邻里居民")).strip() or "邻里居民"; password = str(data.get("password", ""))
        if len(phone) != 11 or not phone.isdigit() or len(password) < 6: return self.send_json({"error": "请输入正确手机号和至少 6 位密码"}, 400)
        salt, digest = hash_password(password); conn = db(); cur = conn.execute("INSERT INTO users(phone,name,role,password_hash,password_salt,created_at) VALUES(?,?,?,?,?,?)", (phone,name,"resident",digest,salt,now())); uid=cur.lastrowid; token=secrets.token_urlsafe(32); conn.execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)", (token,uid,now()+60*60*24*7)); conn.commit(); row=conn.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone(); conn.close(); self.send_json({"token":token,"user":user_public(row),"first_login":True},201)

    def verify_identity(self, user):
        data=self.parse_body(); real_name=str(data.get("real_name","")).strip(); id_card=str(data.get("id_card","")).strip()
        if len(real_name)<2 or len(id_card) not in (15,18) or not id_card.isalnum(): return self.send_json({"error":"请输入真实姓名和有效身份证号"},400)
        conn=db(); conn.execute("UPDATE users SET real_name=?,id_card_last4=?,verified=1,verification_status='已认证' WHERE id=?",(real_name,id_card[-4:],user["id"])); conn.commit(); row=conn.execute("SELECT * FROM users WHERE id=?",(user["id"],)).fetchone(); conn.close(); self.send_json({"user":user_public(row),"message":"实名认证完成，已开启完整互助权限"})

    def admission(self, user):
        data=self.parse_body(); community=str(data.get("community","")).strip(); building=str(data.get("building","")).strip(); unit=str(data.get("unit","")).strip(); resident_type=str(data.get("resident_type","居民")).strip(); accepted=bool(data.get("rules_accepted"))
        if not community or not building or not unit or not accepted: return self.send_json({"error":"请选择社区、填写楼栋单元并同意社区规则"},400)
        conn=db(); conn.execute("UPDATE users SET community=?,building=?,unit=?,resident_type=?,community_status='已通过',rules_accepted=1 WHERE id=?",(community,building,unit,resident_type,user["id"])); conn.commit(); row=conn.execute("SELECT * FROM users WHERE id=?",(user["id"],)).fetchone(); conn.close(); self.send_json({"user":user_public(row),"message":"社区准入完成"})

    def complete_tutorial(self, user):
        data=self.parse_body(); answers=data.get("answers",[]); score=sum(1 for x in answers if x is True)
        if score < 3: return self.send_json({"error":"请完成安全测验后解锁功能"},400)
        conn=db(); conn.execute("UPDATE users SET tutorial_completed=1,points=points+20 WHERE id=? AND tutorial_completed=0",(user["id"],)); conn.commit(); row=conn.execute("SELECT * FROM users WHERE id=?",(user["id"],)).fetchone(); conn.close(); self.send_json({"user":user_public(row),"message":"教程完成，获得 20 个新手积分"})

    def logout(self):
        token = self.headers.get("Authorization", "").replace("Bearer ", "").strip(); conn=db(); conn.execute("DELETE FROM sessions WHERE token=?",(token,)); conn.commit(); conn.close(); self.send_json({"ok":True})

    def tasks(self):
        user = self.auth(False); params = urlparse(self.path).query; from urllib.parse import parse_qs; query=parse_qs(params); q=query.get("q", [""])[0].lower(); category=query.get("category", [""])[0]; urgency=query.get("urgency", [""])[0]; view=query.get("view", [""])[0]
        urgency_order={"危急":0,"紧急":1,"较急":2,"普通":3}
        conn=db(); cutoff=now()-86400; conn.execute("UPDATE tasks SET status='已取消' WHERE status IN ('待接单','已接单','服务中') AND created_at<?",(cutoff,)); conn.commit(); rows=conn.execute("SELECT t.*, o.name owner_name, h.name helper_name FROM tasks t JOIN users o ON o.id=t.owner_id LEFT JOIN users h ON h.id=t.helper_id WHERE (?='' OR lower(t.title||t.description||t.area) LIKE '%'||?||'%') AND (?='' OR t.category=?) AND (?='' OR t.urgency=?) AND (?!='hall' OR t.status NOT IN ('已完成','已取消')) ORDER BY CASE t.urgency WHEN '危急' THEN 0 WHEN '紧急' THEN 1 WHEN '较急' THEN 2 ELSE 3 END, t.created_at DESC",(q,q,category,category,urgency,urgency,view)).fetchall(); result=[]
        for row in rows:
            item=row_dict(row); item["is_mine"]=bool(user and row["owner_id"]==user["id"]); item["can_accept"]=bool(user and row["status"]=="待接单" and row["owner_id"]!=user["id"]); result.append(item)
        conn.close(); self.send_json({"tasks":result})

    def create_task(self, user):
        data=self.parse_body(); required=["title","description","category","area","scheduled_time"]
        if any(not str(data.get(x," ")).strip() for x in required): return self.send_json({"error":"请完整填写求助信息"},400)
        conn=db(); cur=conn.execute("INSERT INTO tasks(title,description,category,urgency,area,scheduled_time,reward,status,owner_id,photo,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(data["title"].strip(),data["description"].strip(),data["category"],data.get("urgency","普通"),data["area"].strip(),data["scheduled_time"].strip(),max(0,int(data.get("reward",10))),"待接单",user["id"],data.get("photo"),now())); tid=cur.lastrowid; conn.execute("INSERT INTO task_events(task_id,actor_id,event_type,note,created_at) VALUES(?,?,?,?,?)",(tid,user["id"],"发布","发布互助需求",now())); conn.commit(); conn.close(); self.send_json({"id":tid},201)

    def create_emergency(self, user):
        data = self.parse_body(); area = str(data.get("area", "我的当前位置")).strip() or "我的当前位置"
        description = str(data.get("description", "需要邻居尽快协助，请先通过电话或消息确认情况。")).strip()
        conn = db(); cur = conn.execute("INSERT INTO tasks(title,description,category,urgency,area,scheduled_time,reward,status,owner_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", ("一键应急帮扶", description, "应急帮扶", "紧急", area, "现在", max(20, int(data.get("reward", 30))), "待接单", user["id"], now()))
        tid = cur.lastrowid
        conn.execute("INSERT INTO task_events(task_id,actor_id,event_type,note,created_at) VALUES(?,?,?,?,?)", (tid, user["id"], "应急求助", "一键发起紧急互助", now()))
        conn.execute("INSERT INTO notifications(user_id,title,body,created_at) SELECT id,?,?,? FROM users WHERE role IN ('volunteer','admin')", ("新的紧急求助", f"{user['name']} 发起了应急帮扶，请就近响应。", now()))
        conn.commit(); conn.close(); self.send_json({"id": tid}, 201)

    def accept_task(self,user,tid):
        conn=db(); task=conn.execute("SELECT * FROM tasks WHERE id=?",(tid,)).fetchone()
        if not task: conn.close(); return self.send_json({"error":"需求不存在"},404)
        if task["owner_id"]==user["id"]: conn.close(); return self.send_json({"error":"不能接取自己发布的需求"},400)
        if task["status"]!="待接单": conn.close(); return self.send_json({"error":"该需求已被接单或关闭"},409)
        conn.execute("UPDATE tasks SET helper_id=?,status='已接单' WHERE id=?",(user["id"],tid)); conn.execute("INSERT INTO task_events(task_id,actor_id,event_type,note,created_at) VALUES(?,?,?,?,?)",(tid,user["id"],"接单","志愿者已接单",now())); conn.execute("INSERT INTO notifications(user_id,title,body,created_at) VALUES(?,?,?,?)",(task["owner_id"],"你的求助有回应了",f"{user['name']} 已接单，点击查看工作进度并开始沟通。",now())); conn.commit(); conn.close(); self.send_json({"ok":True})

    def update_task(self,user,tid):
        data=self.parse_body(); status=data.get("status"); allowed={"已接单":"服务中","服务中":"待确认","待确认":"已完成"}; conn=db(); task=conn.execute("SELECT * FROM tasks WHERE id=?",(tid,)).fetchone()
        if not task or user["id"] not in (task["owner_id"],task["helper_id"]): conn.close(); return self.send_json({"error":"无权操作该订单"},403)
        if status not in ("服务中","待确认","已完成","已取消"): conn.close(); return self.send_json({"error":"不支持的状态"},400)
        transitions={"已接单":{"服务中","待确认","已取消"},"服务中":{"待确认","已取消"},"待确认":{"已完成","服务中"}}
        if status not in transitions.get(task["status"],set()): conn.close(); return self.send_json({"error":"当前状态不能执行该操作"},409)
        if status == "已完成" and user["id"] != task["owner_id"]: conn.close(); return self.send_json({"error":"接单者请先提交完成，等待发布者确认"},403)
        if task["status"] == "已完成": conn.close(); return self.send_json({"error":"该服务已经完成，不能重复结算"},409)
        completion_photo = data.get("completion_photo") if status == "待确认" else None
        conn.execute("UPDATE tasks SET status=?, completion_photo=COALESCE(?, completion_photo) WHERE id=?",(status,completion_photo,tid)); conn.execute("INSERT INTO task_events(task_id,actor_id,event_type,note,created_at) VALUES(?,?,?,?,?)",(tid,user["id"],status,"更新服务状态",now()))
        if status=="已完成":
            helper=task["helper_id"]; reward=task["reward"]; conn.execute("UPDATE users SET points=points+? WHERE id=?",(reward,helper)); conn.execute("INSERT INTO points_ledger(user_id,amount,reason,task_id,created_at) VALUES(?,?,?,?,?)",(helper,reward,"完成互助服务",tid,now())); conn.execute("INSERT INTO notifications(user_id,title,body,created_at) VALUES(?,?,?,?)",(helper,"互助积分到账",f"完成服务获得 {reward} 个积分。",now()))
        conn.commit(); conn.close(); self.send_json({"ok":True})

    def review(self,user,tid):
        data=self.parse_body(); rating=max(1,min(5,int(data.get("rating",5)))); comment=str(data.get("comment","服务很棒，感谢邻居！")).strip(); conn=db(); task=conn.execute("SELECT * FROM tasks WHERE id=?",(tid,)).fetchone()
        if not task or task["status"]!="已完成" or user["id"] not in (task["owner_id"],task["helper_id"]): conn.close(); return self.send_json({"error":"只能评价已完成且与自己相关的服务"},400)
        reviewee=task["helper_id"] if user["id"]==task["owner_id"] else task["owner_id"]; conn.execute("INSERT INTO reviews(task_id,reviewer_id,reviewee_id,rating,comment,created_at) VALUES(?,?,?,?,?,?)",(tid,user["id"],reviewee,rating,comment,now())); avg=conn.execute("SELECT AVG(rating) FROM reviews WHERE reviewee_id=?",(reviewee,)).fetchone()[0]; conn.execute("UPDATE users SET rating=? WHERE id=?",(round(avg,1),reviewee)); conn.commit(); conn.close(); self.send_json({"ok":True})

    def task_detail(self,tid):
        user=self.auth(); conn=db(); task=conn.execute("SELECT t.*,o.name owner_name,h.name helper_name FROM tasks t JOIN users o ON o.id=t.owner_id LEFT JOIN users h ON h.id=t.helper_id WHERE t.id=?",(tid,)).fetchone(); events=conn.execute("SELECT e.*,u.name actor_name FROM task_events e JOIN users u ON u.id=e.actor_id WHERE e.task_id=? ORDER BY e.created_at",(tid,)).fetchall(); conn.close()
        if not task or user["id"] not in (task["owner_id"],task["helper_id"]): return self.send_json({"error":"无权查看该任务"},403)
        self.send_json({"task":row_dict(task),"events":[row_dict(x) for x in events]})

    def messages(self,tid):
        user=self.auth(); conn=db(); task=conn.execute("SELECT owner_id,helper_id FROM tasks WHERE id=?",(tid,)).fetchone()
        if not task or user["id"] not in (task["owner_id"],task["helper_id"]): conn.close(); return self.send_json({"error":"无权查看消息"},403)
        rows=conn.execute("SELECT m.*,u.name sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.task_id=? ORDER BY m.created_at",(tid,)).fetchall(); conn.execute("UPDATE messages SET read=1 WHERE task_id=? AND receiver_id=?",(tid,user["id"])); conn.commit(); conn.close(); self.send_json({"messages":[row_dict(x) for x in rows]})

    def send_message(self,user,tid):
        data=self.parse_body(); body=str(data.get("body","")).strip(); conn=db(); task=conn.execute("SELECT owner_id,helper_id FROM tasks WHERE id=?",(tid,)).fetchone()
        if not body or not task or user["id"] not in (task["owner_id"],task["helper_id"]): conn.close(); return self.send_json({"error":"消息不能为空或无权发送"},400)
        receiver=task["helper_id"] if user["id"]==task["owner_id"] else task["owner_id"]; conn.execute("INSERT INTO messages(task_id,sender_id,receiver_id,body,created_at) VALUES(?,?,?,?,?)",(tid,user["id"],receiver,body,now())); conn.execute("INSERT INTO notifications(user_id,title,body,created_at) VALUES(?,?,?,?)",(receiver,"收到新的任务消息",f"{user['name']}：{body[:35]}",now())); conn.commit(); conn.close(); self.send_json({"ok":True})

    def notifications(self):
        user=self.auth(); conn=db(); rows=conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 20",(user["id"],)).fetchall(); conn.close(); self.send_json({"notifications":[row_dict(x) for x in rows]})

    def mark_notification(self,user,nid):
        conn=db(); conn.execute("UPDATE notifications SET read=1 WHERE id=? AND user_id=?",(nid,user["id"])); conn.commit(); conn.close(); self.send_json({"ok":True})

    def points(self):
        user=self.auth(); conn=db(); rows=conn.execute("SELECT * FROM points_ledger WHERE user_id=? ORDER BY created_at DESC LIMIT 20",(user["id"],)).fetchall(); balance=conn.execute("SELECT points FROM users WHERE id=?",(user["id"],)).fetchone()[0]; conn.close(); self.send_json({"balance":balance,"ledger":[row_dict(x) for x in rows]})

    def stats(self):
        user=self.auth(False); conn=db(); total=conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]; completed=conn.execute("SELECT COUNT(*) FROM tasks WHERE status='已完成'").fetchone()[0]; urgent=conn.execute("SELECT COUNT(*) FROM tasks WHERE urgency='紧急' AND status NOT IN ('已完成','已取消')").fetchone()[0]; volunteers=conn.execute("SELECT COUNT(*) FROM users WHERE role='volunteer'").fetchone()[0]; categories=[row_dict(x) for x in conn.execute("SELECT category,COUNT(*) count FROM tasks GROUP BY category ORDER BY count DESC").fetchall()]; conn.close(); self.send_json({"total_tasks":total,"completed_tasks":completed,"urgent_tasks":urgent,"volunteers":volunteers,"categories":categories})

    def rewards(self):
        conn=db(); rows=conn.execute("SELECT * FROM rewards WHERE stock>0 ORDER BY points").fetchall(); conn.close(); self.send_json({"rewards":[row_dict(x) for x in rows]})

    def redemptions(self):
        user=self.auth(); conn=db(); rows=conn.execute("SELECT r.*, w.name reward_name FROM redemptions r JOIN rewards w ON w.id=r.reward_id WHERE r.user_id=? ORDER BY r.created_at DESC",(user["id"],)).fetchall(); conn.close(); self.send_json({"redemptions":[row_dict(x) for x in rows]})

    def redeem(self,user,rid):
        conn=db(); reward=conn.execute("SELECT * FROM rewards WHERE id=? AND stock>0",(rid,)).fetchone(); balance=conn.execute("SELECT points FROM users WHERE id=?",(user["id"],)).fetchone()[0]
        if not reward: conn.close(); return self.send_json({"error":"礼品暂时缺货"},409)
        if balance<reward["points"]: conn.close(); return self.send_json({"error":f"还差 {reward['points']-balance} 积分"},400)
        conn.execute("UPDATE users SET points=points-? WHERE id=?",(reward["points"],user["id"])); conn.execute("UPDATE rewards SET stock=stock-1 WHERE id=?",(rid,)); conn.execute("INSERT INTO redemptions(user_id,reward_id,points,created_at) VALUES(?,?,?,?)",(user["id"],rid,reward["points"],now())); conn.execute("INSERT INTO points_ledger(user_id,amount,reason,created_at) VALUES(?,?,?,?)",(user["id"],-reward["points"],f"兑换礼品：{reward['name']}",now())); conn.commit(); conn.close(); self.send_json({"ok":True,"message":f"已兑换 {reward['name']}，请留意社区领取通知"})


if __name__ == "__main__":
    init_db()
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        local_ip = "本机局域网IP"
    print("邻里智助运行中: http://127.0.0.1:5173")
    print(f"同一 Wi-Fi 下的手机/电脑请访问: http://{local_ip}:5173")
    import os

PORT = int(os.environ.get("PORT", "5173"))
ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
