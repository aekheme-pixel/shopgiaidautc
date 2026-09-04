const json = (data, status=200) =>
  new Response(JSON.stringify(data), {
    status,
    headers:{
      "content-type":"application/json; charset=utf-8",
      "cache-control":"no-store"
    }
  });

function b64u(bytes){
  return btoa(
    String.fromCharCode(...new Uint8Array(bytes))
  )
  .replace(/\+/g,"-")
  .replace(/\//g,"_")
  .replace(/=+$/,"");
}

function unb64u(s){
  s=s.replace(/-/g,"+").replace(/_/g,"/");
  while(s.length%4)s+="=";
  return Uint8Array.from(atob(s),c=>c.charCodeAt(0));
}

async function hashPassword(password){

  const salt=crypto.getRandomValues(
    new Uint8Array(16)
  );

  const key=await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits=await crypto.subtle.deriveBits(
    {
      name:"PBKDF2",
      salt,
      iterations:150000,
      hash:"SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$150000$${b64u(salt)}$${b64u(bits)}`;
}

async function verifyPassword(password,stored){

  const [,it,saltS,hashS]=stored.split("$");

  const key=await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits=await crypto.subtle.deriveBits(
    {
      name:"PBKDF2",
      salt:unb64u(saltS),
      iterations:Number(it),
      hash:"SHA-256"
    },
    key,
    256
  );

  return b64u(bits)===hashS;
}

async function sessionUser(request,env){

  const token=
    request.headers
      .get("Authorization")
      ?.replace(/^Bearer\s+/i,"")
    ||
    request.headers
      .get("Cookie")
      ?.match(/session=([^;]+)/)?.[1];

  if(!token)
    return null;

  const row=await env.DB
    .prepare(`
      SELECT
        u.id,
        u.email,
        u.role
      FROM sessions s
      JOIN users u ON u.id=s.user_id
      WHERE s.token=?
      AND s.expires_at>?
    `)
    .bind(token,Date.now())
    .first();

  return row
    ? {...row,token}
    : null;
}

async function requireAuth(req,env){

  const u=await sessionUser(req,env);

  if(!u)
    throw new Response("Unauthorized",{status:401});

  return u;
}

async function requireAdmin(req,env){

  const u=await requireAuth(req,env);

  if(
    u.role!=="ADMIN" &&
    u.role!=="SUPER_ADMIN"
  )
    throw new Response("Forbidden",{status:403});

  return u;
}

function code(){

  return "REG-"+
    Date.now().toString(36).toUpperCase()+
    "-"+
    Math.random()
      .toString(36)
      .slice(2,7)
      .toUpperCase();
}

async function api(req,env){

  const url=new URL(req.url);
  const path=url.pathname;
  const method=req.method;

  try{

    if(path==="/api/health"){

      return json({
        ok:true,
        time:new Date().toISOString()
      });
    }

    if(
      path==="/api/auth/register" &&
      method==="POST"
    ){

      const {email,password}=await req.json();

      if(
        !email ||
        !password ||
        password.length<8
      )
        return json({
          error:"Email và mật khẩu tối thiểu 8 ký tự"
        },400);

      const normalized=email.toLowerCase();

      const existing=await env.DB
        .prepare(
          "SELECT id FROM users WHERE email=?"
        )
        .bind(normalized)
        .first();

      if(existing)
        return json({
          error:"Email đã tồn tại"
        },409);

      const h=await hashPassword(password);

      const r=await env.DB
        .prepare(`
          INSERT INTO users
          (email,password_hash)
          VALUES(?,?)
        `)
        .bind(normalized,h)
        .run();

      return json({
        ok:true,
        userId:r.meta.last_row_id
      },201);
    }

    if(
      path==="/api/auth/login" &&
      method==="POST"
    ){

      const {email,password}=await req.json();

      const u=await env.DB
        .prepare(
          "SELECT * FROM users WHERE email=?"
        )
        .bind((email||"").toLowerCase())
        .first();

      if(
        !u ||
        !(await verifyPassword(
          password||"",
          u.password_hash
        ))
      )
        return json({
          error:"Sai email hoặc mật khẩu"
        },401);

      const token=
        crypto.randomUUID()+
        crypto.randomUUID();

      await env.DB
        .prepare(`
          INSERT INTO sessions
          (token,user_id,expires_at)
          VALUES(?,?,?)
        `)
        .bind(
          token,
          u.id,
          Date.now()+30*24*3600*1000
        )
        .run();

      return new Response(
        JSON.stringify({
          ok:true,
          user:{
            id:u.id,
            email:u.email,
            role:u.role
          }
        }),
        {
          headers:{
            "content-type":
              "application/json",
            "Set-Cookie":
              `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`
          }
        }
      );
    }

    if(path==="/api/auth/me"){

      const u=await sessionUser(req,env);

      return json({
        user:u
          ? {
              id:u.id,
              email:u.email,
              role:u.role
            }
          : null
      });
    }

    if(path==="/api/auth/logout"){

      const u=await sessionUser(req,env);

      if(u){

        await env.DB
          .prepare(
            "DELETE FROM sessions WHERE token=?"
          )
          .bind(u.token)
          .run();
      }

      return new Response(null,{
        status:204,
        headers:{
          "Set-Cookie":
            "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
        }
      });
    }

    if(
      path==="/api/tournaments" &&
      method==="GET"
    ){

      const rows=await env.DB
        .prepare(
          "SELECT * FROM tournaments ORDER BY id DESC"
        )
        .all();

      return json({
        tournaments:rows.results
      });
    }

    if(
      path==="/api/tournaments" &&
      method==="POST"
    ){

      const u=await requireAdmin(req,env);
      const b=await req.json();

      if(!b.name)
        return json({
          error:"Tên giải là bắt buộc"
        },400);

      const r=await env.DB
        .prepare(`
          INSERT INTO tournaments
          (name,fee,max_teams,description)
          VALUES(?,?,?,?)
        `)
        .bind(
          b.name,
          Number(b.fee||0),
          Number(b.max_teams||48),
          b.description||""
        )
        .run();

      await env.DB
        .prepare(`
          INSERT INTO audit_logs
          (user_id,action,target,details)
          VALUES(?,?,?,?)
        `)
        .bind(
          u.id,
          "CREATE_TOURNAMENT",
          String(r.meta.last_row_id),
          JSON.stringify(b)
        )
        .run();

      return json({
        id:r.meta.last_row_id
      },201);
    }

    if(
      path==="/api/slots" &&
      method==="GET"
    ){

      const tid=
        url.searchParams.get(
          "tournament_id"
        );

      const rows=await env.DB
        .prepare(`
          SELECT *
          FROM slots
          WHERE tournament_id=?
          ORDER BY slot_time
        `)
        .bind(tid)
        .all();

      return json({
        slots:rows.results
      });
    }

    if(
      path==="/api/slots" &&
      method==="POST"
    ){

      await requireAdmin(req,env);

      const b=await req.json();

      const r=await env.DB
        .prepare(`
          INSERT INTO slots
          (tournament_id,slot_time,group_name,capacity)
          VALUES(?,?,?,?)
        `)
        .bind(
          b.tournament_id,
          b.slot_time,
          b.group_name,
          b.capacity||12
        )
        .run();

      return json({
        id:r.meta.last_row_id
      },201);
    }

    if(
      path==="/api/teams" &&
      method==="POST"
    ){

      const u=await requireAuth(req,env);
      const b=await req.json();

      if(
        !b.name ||
        !Array.isArray(b.members) ||
        b.members.length<1
      )
        return json({
          error:
            "Tên đội và ít nhất 1 thành viên"
        },400);

      const r=await env.DB
        .prepare(`
          INSERT INTO teams
          (owner_id,name,tag,logo_url)
          VALUES(?,?,?,?)
        `)
        .bind(
          u.id,
          b.name,
          b.tag||"",
          b.logo_url||""
        )
        .run();

      const tid=r.meta.last_row_id;

      for(
        const m of b.members.slice(0,5)
      ){

        if(!m.game_name || !m.uid)
          continue;

        await env.DB
          .prepare(`
            INSERT INTO team_members
            (team_id,game_name,uid,role)
            VALUES(?,?,?,?)
          `)
          .bind(
            tid,
            m.game_name,
            m.uid,
            m.role||"PLAYER"
          )
          .run();
      }

      return json({
        id:tid
      },201);
    }

    if(
      path==="/api/teams" &&
      method==="GET"
    ){

      const u=await requireAuth(req,env);

      const rows=await env.DB
        .prepare(`
          SELECT *
          FROM teams
          WHERE owner_id=?
          ORDER BY id DESC
        `)
        .bind(u.id)
        .all();

      return json({
        teams:rows.results
      });
    }

    if(
      path==="/api/admin/teams" &&
      method==="GET"
    ){

      await requireAdmin(req,env);

      const rows=await env.DB
        .prepare(`
          SELECT
            t.*,
            u.email owner_email
          FROM teams t
          JOIN users u
            ON u.id=t.owner_id
          ORDER BY t.id DESC
        `)
        .all();

      return json({
        teams:rows.results
      });
    }

    if(
      path==="/api/admin/teams/status" &&
      method==="POST"
    ){

      const u=await requireAdmin(req,env);
      const b=await req.json();

      const allowed=[
        "PENDING",
        "APPROVED",
        "REJECTED"
      ];

      if(!allowed.includes(b.status))
        return json({
          error:"Trạng thái không hợp lệ"
        },400);

      await env.DB
        .prepare(`
          UPDATE teams
          SET status=?
          WHERE id=?
        `)
        .bind(
          b.status,
          b.team_id
        )
        .run();

      await env.DB
        .prepare(`
          INSERT INTO audit_logs
          (user_id,action,target,details)
          VALUES(?,?,?,?)
        `)
        .bind(
          u.id,
          "UPDATE_TEAM_STATUS",
          String(b.team_id),
          JSON.stringify(b)
        )
        .run();

      return json({ok:true});
    }

    if(
      path==="/api/registrations" &&
      method==="POST"
    ){

      const u=await requireAuth(req,env);
      const b=await req.json();

      const team=await env.DB
        .prepare(`
          SELECT *
          FROM teams
          WHERE id=?
          AND owner_id=?
        `)
        .bind(
          b.team_id,
          u.id
        )
        .first();

      const t=await env.DB
        .prepare(`
          SELECT *
          FROM tournaments
          WHERE id=?
          AND status="OPEN"
        `)
        .bind(b.tournament_id)
        .first();

      if(!team || !t)
        return json({
          error:"Đội hoặc giải không hợp lệ"
        },400);

      const existing=await env.DB
        .prepare(`
          SELECT id
          FROM registrations
          WHERE team_id=?
          AND tournament_id=?
          AND status NOT IN
          ("CANCELLED","REJECTED")
        `)
        .bind(
          team.id,
          t.id
        )
        .first();

      if(existing)
        return json({
          error:"Đội đã đăng ký giải này"
        },409);

      const c=code();

      const r=await env.DB
        .prepare(`
          INSERT INTO registrations
          (team_id,tournament_id,slot_id,order_code,amount)
          VALUES(?,?,?,?,?)
        `)
        .bind(
          team.id,
          t.id,
          b.slot_id||null,
          c,
          t.fee
        )
        .run();

      return json({
        id:r.meta.last_row_id,
        order_code:c,
        amount:t.fee,
        status:"AWAITING_PAYMENT"
      },201);
    }

    if(
      path==="/api/registrations" &&
      method==="GET"
    ){

      const u=await requireAuth(req,env);

      const rows=await env.DB
        .prepare(`
          SELECT
            r.*,
            t.name team_name,
            tr.name tournament_name
          FROM registrations r
          JOIN teams t
            ON t.id=r.team_id
          JOIN tournaments tr
            ON tr.id=r.tournament_id
          WHERE t.owner_id=?
          ORDER BY r.id DESC
        `)
        .bind(u.id)
        .all();

      return json({
        registrations:rows.results
      });
    }

    if(
      path==="/api/payments" &&
      method==="POST"
    ){

      const u=await requireAuth(req,env);
      const b=await req.json();

      const r=await env.DB
        .prepare(`
          SELECT
            r.*
          FROM registrations r
          JOIN teams t
            ON t.id=r.team_id
          WHERE r.id=?
          AND t.owner_id=?
        `)
        .bind(
          b.registration_id,
          u.id
        )
        .first();

      if(!r)
        return json({
          error:"Đơn không hợp lệ"
        },400);

      const p=await env.DB
        .prepare(`
          INSERT INTO payments
          (registration_id,amount,status)
          VALUES(?,?,?)
        `)
        .bind(
          r.id,
          r.amount,
          "PENDING"
        )
        .run();

      return json({
        id:p.meta.last_row_id,
        order_code:r.order_code,
        amount:r.amount,
        status:"PENDING"
      },201);
    }

    if(
      path==="/api/admin/payments" &&
      method==="GET"
    ){

      await requireAdmin(req,env);

      const rows=await env.DB
        .prepare(`
          SELECT
            p.*,
            r.order_code,
            t.name team_name,
            tr.name tournament_name
          FROM payments p
          JOIN registrations r
            ON r.id=p.registration_id
          JOIN teams t
            ON t.id=r.team_id
          JOIN tournaments tr
            ON tr.id=r.tournament_id
          ORDER BY p.id DESC
        `)
        .all();

      return json({
        payments:rows.results
      });
    }

    if(
      path==="/api/admin/payments/status" &&
      method==="POST"
    ){

      const u=await requireAdmin(req,env);
      const b=await req.json();

      const allowed=[
        "PENDING",
        "PAID",
        "REJECTED"
      ];

      if(!allowed.includes(b.status))
        return json({
          error:"Trạng thái không hợp lệ"
        },400);

      await env.DB
        .prepare(`
          UPDATE payments
          SET status=?
          WHERE id=?
        `)
        .bind(
          b.status,
          b.payment_id
        )
        .run();

      const p=await env.DB
        .prepare(`
          SELECT registration_id
          FROM payments
          WHERE id=?
        `)
        .bind(b.payment_id)
        .first();

      if(p){

        const registrationStatus=
          b.status==="PAID"
            ?"PAID"
            :b.status==="REJECTED"
              ?"REJECTED"
              :"AWAITING_PAYMENT";

        await env.DB
          .prepare(`
            UPDATE registrations
            SET status=?
            WHERE id=?
          `)
          .bind(
            registrationStatus,
            p.registration_id
          )
          .run();
      }

      await env.DB
        .prepare(`
          INSERT INTO audit_logs
          (user_id,action,target,details)
          VALUES(?,?,?,?)
        `)
        .bind(
          u.id,
          "UPDATE_PAYMENT_STATUS",
          String(b.payment_id),
          JSON.stringify(b)
        )
        .run();

      return json({
        ok:true
      });
    }

    /*
      WEBHOOK NGÂN HÀNG

      Đây là endpoint để kết nối provider
      thanh toán thật sau khi cấu hình.
    */

    if(
      path==="/api/webhooks/bank" &&
      method==="POST"
    ){

      const secret=env.BANK_WEBHOOK_SECRET;

      if(
        secret &&
        req.headers.get("x-webhook-secret")!==secret
      )
        return json({
          error:"Invalid webhook secret"
        },401);

      const b=await req.json();

      const content=
        (b.description||b.content||"")+
        " "+
        (b.referenceCode||b.code||"");

      const m=
        content.match(/REG-[A-Z0-9-]+/i);

      if(!m)
        return json({
          ok:true,
          matched:false
        });

      const order=m[0].toUpperCase();

      const r=await env.DB
        .prepare(`
          SELECT *
          FROM registrations
          WHERE order_code=?
        `)
        .bind(order)
        .first();

      if(!r)
        return json({
          ok:true,
          matched:false,
          reason:"order_not_found"
        });

      const amount=Number(
        b.amount ||
        b.transferAmount ||
        0
      );

      if(amount<Number(r.amount))
        return json({
          ok:false,
          reason:"amount_too_low"
        },400);

      await env.DB
        .prepare(`
          INSERT INTO payments
          (registration_id,external_id,amount,status,raw_json)
          VALUES(?,?,?,?,?)
        `)
        .bind(
          r.id,
          String(
            b.id ||
            b.transactionId ||
            ""
          ),
          amount,
          "PAID",
          JSON.stringify(b)
        )
        .run();

      await env.DB
        .prepare(`
          UPDATE registrations
          SET status="PAID"
          WHERE id=?
        `)
        .bind(r.id)
        .run();

      return json({
        ok:true,
        matched:true,
        registration_id:r.id
      });
    }

    /*
      TẠO SUPER ADMIN LẦN ĐẦU
    */

    if(
      path==="/api/admin/bootstrap" &&
      method==="POST"
    ){

      if(!env.ADMIN_BOOTSTRAP_SECRET)
        return json({
          error:
            "ADMIN_BOOTSTRAP_SECRET chưa cấu hình"
        },503);

      const b=await req.json();

      if(
        b.secret !==
        env.ADMIN_BOOTSTRAP_SECRET
      )
        return json({
          error:"Sai secret"
        },403);

      if(
        !b.email ||
        !b.password ||
        b.password.length<8
      )
        return json({
          error:"Thông tin admin không hợp lệ"
        },400);

      const email=b.email.toLowerCase();

      const exists=await env.DB
        .prepare(
          "SELECT id FROM users WHERE email=?"
        )
        .bind(email)
        .first();

      if(exists)
        return json({
          error:"Email đã tồn tại"
        },409);

      const h=
        await hashPassword(b.password);

      const r=await env.DB
        .prepare(`
          INSERT INTO users
          (email,password_hash,role)
          VALUES(?,?,?)
        `)
        .bind(
          email,
          h,
          "SUPER_ADMIN"
        )
        .run();

      return json({
        ok:true,
        id:r.meta.last_row_id
      },201);
    }

    return json({
      error:"Not found"
    },404);

  }catch(e){

    if(e instanceof Response)
      return e;

    return json({
      error:String(
        e?.message||e
      )
    },500);
  }
}

export default {

  async fetch(req,env){

    const url=new URL(req.url);

    if(
      url.pathname.startsWith("/api/")
    )
      return api(req,env);

    return env.ASSETS.fetch(req);
  }
};
