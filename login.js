let generatedOTP = "";

// LOGIN
function login() {
    let user = document.getElementById("username").value;
    let pass = document.getElementById("password").value;
    let msg = document.getElementById("message");

    if (user === "" || pass === "") {
        msg.innerText = "❌ Enter credentials";
        msg.style.color = "red";
        return;
    }

    // SAVE LOG
    let data = {
        username: user,
        password: pass,
        time: new Date().toLocaleString()
    };

    let stored = JSON.parse(localStorage.getItem("logs")) || [];
    stored.push(data);
    localStorage.setItem("logs", JSON.stringify(stored));

    // GENERATE OTP
    generatedOTP = Math.floor(1000 + Math.random() * 9000);

    // SHOW OTP POPUP
    document.getElementById("otpText").innerText = generatedOTP;

    let popup = document.getElementById("otpPopup");
    popup.style.display = "block";

    setTimeout(() => {
        popup.style.display = "none";
    }, 3000);

    msg.innerText = "OTP generated (check top right)";
    msg.style.color = "#00ffcc";

    document.getElementById("loginForm").style.display = "none";
    document.getElementById("otpForm").style.display = "block";
}

// VERIFY OTP
function verifyOTP() {
    let otp = document.getElementById("otp").value;
    let msg = document.getElementById("message");

    if (otp == generatedOTP) {
        msg.innerText = "✔ Access Granted";
        msg.style.color = "#00ffcc";

        localStorage.setItem("loggedIn", "true");

        setTimeout(() => {
            window.location.href = "index.html";
        }, 1200);

    } else {
        msg.innerText = "❌ Wrong OTP";
        msg.style.color = "red";
    }
}

// SHOW PASSWORD
function togglePass() {
    let x = document.getElementById("password");
    x.type = x.type === "password" ? "text" : "password";
}