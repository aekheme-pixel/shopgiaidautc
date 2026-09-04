<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>Giải Đấu Vua Tử Chiến — Mùa 1</title>

  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background: #070707;
      color: #fff;
      font-family: Arial, Helvetica, sans-serif;
    }

    button,
    input,
    select {
      font: inherit;
    }

    button {
      cursor: pointer;
    }

    .navbar {
      position: sticky;
      top: 0;
      z-index: 100;
      background: rgba(7,7,7,.95);
      border-bottom: 1px solid #292929;
      backdrop-filter: blur(10px);
    }

    .nav-container {
      max-width: 1150px;
      margin: auto;
      padding: 16px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .logo {
      font-size: 22px;
      font-weight: 900;
      letter-spacing: 1px;
    }

    .logo span {
      color: #e50920;
    }

    .nav-links {
      display: flex;
      gap: 22px;
      align-items: center;
    }

    .nav-links a {
      color: #aaa;
      text-decoration: none;
      font-size: 14px;
      font-weight: 700;
    }

    .nav-links a:hover {
      color: #fff;
    }

    .btn {
      border: 0;
      border-radius: 8px;
      padding: 12px 20px;
      font-weight: 800;
      color: white;
    }

    .btn-red {
      background: #e50920;
    }

    .btn-red:hover {
      background: #ff142d;
    }

    .btn-dark {
      background: #151515;
      border: 1px solid #333;
    }

    .hero {
      max-width: 1150px;
      margin: auto;
      padding: 90px 20px 60px;
      text-align: center;
    }

    .badge {
      display: inline-block;
      padding: 8px 15px;
      border: 1px solid #6b4f00;
      border-radius: 6px;
      color: #ffc400;
      font-weight: 800;
      font-size: 13px;
      letter-spacing: 1px;
    }

    .hero h1 {
      margin-top: 25px;
      font-size: clamp(45px, 9vw, 92px);
      line-height: .95;
      font-weight: 1000;
      letter-spacing: -4px;
    }

    .hero h1 span {
      color: #e50920;
    }

    .hero p {
      max-width: 700px;
      margin: 25px auto;
      color: #aaa;
      font-size: 18px;
      line-height: 1.7;
    }

    .hero-buttons {
      display: flex;
      justify-content: center;
      gap: 12px;
      flex-wrap: wrap;
    }

    .stats {
      max-width: 1080px;
      margin: auto;
      display: grid;
      grid-template-columns: repeat(4,1fr);
      border: 1px solid #292929;
      background: #111;
    }

    .stat {
      padding: 25px;
      text-align: center;
      border-right: 1px solid #292929;
    }

    .stat:last-child {
      border-right: 0;
    }

    .stat strong {
      display: block;
      font-size: 34px;
      color: #e50920;
    }

    .stat small {
      color: #888;
    }

    .section {
      max-width: 1080px;
      margin: auto;
      padding: 70px 20px;
    }

    .section h2 {
      font-size: 40px;
      margin-bottom: 8px;
    }

    .section h2 span {
      color: #e50920;
    }

    .subtitle {
      color: #888;
      margin-bottom: 25px;
    }

    .tournament-grid {
      display: grid;
      grid-template-columns: repeat(3,1fr);
      gap: 16px;
    }

    .card {
      background: #111;
      border: 1px solid #292929;
      border-radius: 12px;
      padding: 22px;
    }

    .card h3 {
      margin-bottom: 12px;
      font-size: 20px;
    }

    .card p {
      color: #999;
      line-height: 1.5;
    }

    .fee {
      margin: 18px 0;
      color: #ffc400;
      font-size: 27px;
      font-weight: 900;
    }

    .modal {
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,.8);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      z-index: 1000;
    }

    .modal-box {
      width: min(520px,100%);
      background: #131313;
      border: 1px solid #333;
      border-radius: 14px;
      padding: 25px;
    }

    .modal-box h2 {
      margin-bottom: 20px;
    }

    .close {
      float: right;
      background: #222;
      color: #fff;
      border: 1px solid #333;
      border-radius: 7px;
      padding: 7px 10px;
    }

    label {
      display: block;
      margin: 14px 0 7px;
      color: #aaa;
    }

    input,
    select {
      width: 100%;
      padding: 12px;
      background: #080808;
      color: #fff;
      border: 1px solid #333;
      border-radius: 7px;
      outline: none;
    }

    input:focus,
    select:focus {
      border-color: #e50920;
    }

    .full {
      width: 100%;
      margin-top: 18px;
    }

    .hidden {
      display: none !important;
    }

    footer {
      border-top: 1px solid #222;
      padding: 40px 20px;
      text-align: center;
      color: #666;
    }

    @media(max-width:800px) {
      .nav-links {
        display: none;
      }

      .stats {
        margin: 0 20px;
        grid-template-columns: repeat(2,1fr);
      }

      .stat:nth-child(2) {
        border-right: 0;
      }

      .stat:nth-child(3),
      .stat:nth-child(4) {
        border-top: 1px solid #292929;
      }

      .tournament-grid {
        grid-template-columns: 1fr;
      }

      .hero {
        padding-top: 60px;
      }
    }
  </style>
</head>

<body>

<header class="navbar">
  <div class="nav-container">

    <div class="logo">
      VUA TỬ CHIẾN <span>01</span>
    </div>

    <nav class="nav-links">
      <a href="#giai-dau">GIẢI ĐẤU</a>
      <a href="#lich">LỊCH THI ĐẤU</a>
      <a href="#bxh">XẾP HẠNG</a>
      <button class="btn btn-red" onclick="openLogin()">
        ĐĂNG NHẬP
      </button>
    </nav>

  </div>
</header>

<main>

<section class="hero">

  <div class="badge">
    FREE FIRE • GIẢI ĐẤU CỘNG ĐỒNG
  </div>

  <h1>
    VUA TỬ CHIẾN
    <span>MÙA 1</span>
  </h1>

  <p>
    Nền tảng giải đấu Free Fire với hệ thống đăng ký đội,
    thanh toán, duyệt đơn, lịch thi đấu và bảng xếp hạng.
  </p>

  <div class="hero-buttons">

    <button
      class="btn btn-red"
      onclick="openLogin()"
    >
      ĐĂNG KÝ ĐỘI
    </button>

    <a
      class="btn btn-dark"
      href="#giai-dau"
      style="text-decoration:none"
    >
      XEM GIẢI
    </a>

  </div>

</section>


<section class="stats">

  <div class="stat">
    <strong id="openTournament">0</strong>
    <small>GIẢI ĐANG MỞ</small>
  </div>

  <div class="stat">
    <strong id="teamCount">0</strong>
    <small>ĐỘI CỦA BẠN</small>
  </div>

  <div class="stat">
    <strong>24/7</strong>
    <small>ONLINE</small>
  </div>

  <div class="stat">
    <strong>LIVE</strong>
    <small>CẬP NHẬT</small>
  </div>

</section>


<section
  class="section"
  id="giai-dau"
>

  <h2>
    GIẢI <span>ĐẤU</span>
  </h2>

  <p class="subtitle">
    Đăng ký giải đấu Free Fire
  </p>

  <div
    id="tournamentList"
    class="tournament-grid"
  >
    <div class="card">
      Đang tải giải đấu...
    </div>
  </div>

</section>


<section
  class="section"
  id="lich"
>

  <h2>
    LỊCH <span>THI ĐẤU</span>
  </h2>

  <p class="subtitle">
    Lịch thi đấu được cập nhật trực tiếp từ hệ thống.
  </p>

  <div class="card">

    <p>
      Lịch thi đấu sẽ xuất hiện sau khi ban tổ chức
      mở bảng đấu.
    </p>

  </div>

</section>


<section
  class="section"
  id="bxh"
>

  <h2>
    BẢNG <span>XẾP HẠNG</span>
  </h2>

  <p class="subtitle">
    Thành tích các đội tuyển.
  </p>

  <div class="card">

    <p>
      Chưa có kết quả thi đấu.
    </p>

  </div>

</section>

</main>


<footer>

  GIẢI ĐẤU VUA TỬ CHIẾN — MÙA 1

</footer>


<div
  id="modal"
  class="modal hidden"
>

  <div class="modal-box">

    <button
      class="close"
      onclick="closeModal()"
    >
      ✕
    </button>

    <div id="modalContent"></div>

  </div>

</div>


<script>

const API = "/api";


function closeModal() {

  document
    .getElementById("modal")
    .classList.add("hidden");

}


function showModal(html) {

  document
    .getElementById("modalContent")
    .innerHTML = html;

  document
    .getElementById("modal")
    .classList.remove("hidden");

}


function openLogin() {

  showModal(`

    <h2>Đăng nhập</h2>

    <form onsubmit="login(event)">

      <label>Email</label>

      <input
        id="loginEmail"
        type="email"
        required
      >

      <label>Mật khẩu</label>

      <input
        id="loginPassword"
        type="password"
        required
      >

      <button
        class="btn btn-red full"
      >
        ĐĂNG NHẬP
      </button>

    </form>

    <p style="
      margin-top:15px;
      color:#888
    ">
      Chưa có tài khoản?
      <a
        href="#"
        onclick="openRegister()"
        style="color:#e50920"
      >
        Đăng ký
      </a>
    </p>

  `);

}


function openRegister() {

  showModal(`

    <h2>Tạo tài khoản</h2>

    <form onsubmit="register(event)">

      <label>Email</label>

      <input
        id="registerEmail"
        type="email"
        required
      >

      <label>Mật khẩu</label>

      <input
        id="registerPassword"
        type="password"
        minlength="8"
        required
      >

      <button
        class="btn btn-red full"
      >
        TẠO TÀI KHOẢN
      </button>

    </form>

  `);

}


async function apiFetch(
  path,
  options = {}
) {

  const response =
    await fetch(
      API + path,
      {
        ...options,
        headers: {
          "Content-Type":
            "application/json",
          ...(options.headers || {})
        }
      }
    );

  const data =
    await response
      .json()
      .catch(() => ({}));

  if (!response.ok) {

    throw new Error(
      data.error ||
      "Có lỗi xảy ra."
    );

  }

  return data;

}


async function register(event) {

  event.preventDefault();

  try {

    await apiFetch(
      "/auth/register",
      {
        method:"POST",

        body:JSON.stringify({
          email:
            document
              .getElementById(
                "registerEmail"
              ).value,

          password:
            document
              .getElementById(
                "registerPassword"
              ).value
        })
      }
    );

    alert(
      "Tạo tài khoản thành công!"
    );

    openLogin();

  }

  catch(error) {

    alert(error.message);

  }

}


async function login(event) {

  event.preventDefault();

  try {

    const data =
      await apiFetch(
        "/auth/login",
        {
          method:"POST",

          body:JSON.stringify({
            email:
              document
                .getElementById(
                  "loginEmail"
                ).value,

            password:
              document
                .getElementById(
                  "loginPassword"
                ).value
          })
        }
      );

    closeModal();

    if (
      data.user.role === "ADMIN" ||
      data.user.role === "SUPER_ADMIN"
    ) {

      window.location.href =
        "/admin.html";

    } else {

      alert(
        "Đăng nhập thành công!"
      );

      loadData();

    }

  }

  catch(error) {

    alert(error.message);

  }

}


async function loadData() {

  try {

    const data =
      await apiFetch(
        "/tournaments"
      );

    const tournaments =
      data.tournaments || [];

    const open =
      tournaments.filter(
        x => x.status === "OPEN"
      );

    document
      .getElementById(
        "openTournament"
      )
      .textContent =
      open.length;

    const container =
      document.getElementById(
        "tournamentList"
      );

    if (!tournaments.length) {

      container.innerHTML = `

        <div class="card">

          <h3>
            Vua Tử Chiến — Mùa 1
          </h3>

          <p>
            Ban tổ chức chưa mở đăng ký.
          </p>

        </div>

      `;

      return;

    }

    container.innerHTML =
      tournaments.map(
        tournament => `

          <article class="card">

            <h3>
              ${escapeHtml(
                tournament.name
              )}
            </h3>

            <p>
              ${escapeHtml(
                tournament.description ||
                "Giải đấu Free Fire"
              )}
            </p>

            <div class="fee">

              ${Number(
                tournament.fee || 0
              ).toLocaleString(
                "vi-VN"
              )}đ

            </div>

            <p style="margin-bottom:15px">

              Tối đa
              ${tournament.max_teams}
              đội

            </p>

            <button
              class="btn btn-red"
              onclick="joinTournament(
                ${tournament.id}
              )"
            >
              ĐĂNG KÝ

            </button>

          </article>

        `
      ).join("");

  }

  catch(error) {

    console.error(error);

  }


  try {

    const me =
      await apiFetch(
        "/auth/me"
      );

    if (!me.user)
      return;

    const teams =
      await apiFetch(
        "/teams"
      );

    document
      .getElementById(
        "teamCount"
      )
      .textContent =
      teams.teams.length;

  }

  catch(error) {

    console.error(error);

  }

}


async function joinTournament(
  tournamentId
) {

  try {

    const me =
      await apiFetch(
        "/auth/me"
      );

    if (!me.user) {

      openLogin();

      return;

    }

    const teams =
      await apiFetch(
        "/teams"
      );

    if (!teams.teams.length) {

      showModal(`

        <h2>Tạo đội tuyển</h2>

        <form
          onsubmit="
            createTeam(
              event,
              ${tournamentId}
            )
          "
        >

          <label>
            Tên đội
          </label>

          <input
            id="teamName"
            required
          >

          <label>
            TAG
          </label>

          <input
            id="teamTag"
          >

          <label>
            Tên nhân vật
          </label>

          <input
            id="gameName"
            required
          >

          <label>
            UID Free Fire
          </label>

          <input
            id="gameUid"
            required
          >

          <button
            class="btn btn-red full"
          >
            TẠO ĐỘI & ĐĂNG KÝ
          </button>

        </form>

      `);

      return;

    }

    showModal(`

      <h2>
        Đăng ký giải đấu
      </h2>

      <label>
        Chọn đội
      </label>

      <select id="selectedTeam">

        ${teams.teams.map(
          team => `

            <option
              value="${team.id}"
            >
              ${escapeHtml(
                team.name
              )}
            </option>

          `
        ).join("")}

      </select>

      <button
        class="btn btn-red full"
        onclick="
          submitRegistration(
            ${tournamentId}
          )
        "
      >
        TIẾP TỤC
      </button>

    `);

  }

  catch(error) {

    alert(error.message);

  }

}


async function createTeam(
  event,
  tournamentId
) {

  event.preventDefault();

  try {

    const team =
      await apiFetch(
        "/teams",
        {
          method:"POST",

          body:JSON.stringify({

            name:
              document
                .getElementById(
                  "teamName"
                ).value,

            tag:
              document
                .getElementById(
                  "teamTag"
                ).value,

            members:[{

              game_name:
                document
                  .getElementById(
                    "gameName"
                  ).value,

              uid:
                document
                  .getElementById(
                    "gameUid"
                  ).value

            }]

          })
        }
      );

    await submitRegistration(
      tournamentId,
      team.id
    );

  }

  catch(error) {

    alert(error.message);

  }

}


async function submitRegistration(
  tournamentId,
  forcedTeamId = null
) {

  try {

    const teamId =
      forcedTeamId ||
      Number(
        document
          .getElementById(
            "selectedTeam"
          ).value
      );

    const order =
      await apiFetch(
        "/registrations",
        {
          method:"POST",

          body:JSON.stringify({

            team_id:
              teamId,

            tournament_id:
              tournamentId

          })
        }
      );

    showModal(`

      <h2>
        ĐƠN ĐĂNG KÝ
      </h2>

      <p style="color:#aaa">
        Mã đơn:
      </p>

      <h3 style="
        margin:8px 0;
        color:#ffc400
      ">
        ${escapeHtml(
          order.order_code
        )}
      </h3>

      <p style="
        color:#aaa;
        margin-top:15px
      ">
        Số tiền:
      </p>

      <h2>
        ${Number(
          order.amount
        ).toLocaleString(
          "vi-VN"
        )}đ
      </h2>

      <p style="
        color:#888;
        margin-top:15px;
        line-height:1.5
      ">
        Hệ thống đã tạo đơn.
        Tiếp theo bạn sẽ thực hiện
        thanh toán theo thông tin
        tài khoản của ban tổ chức.
      </p>

    `);

  }

  catch(error) {

    alert(error.message);

  }

}


function escapeHtml(value) {

  return String(
    value ?? ""
  ).replace(
    /[&<>"']/g,
    character => ({

      "&":"&amp;",
      "<":"&lt;",
      ">":"&gt;",
      '"':"&quot;",
      "'":"&#039;"

    }[character])
  );

}


loadData();

</script>

</body>
</html>
