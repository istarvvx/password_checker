const pw = document.getElementById("pw");
const btn = document.getElementById("check");
const meter = document.getElementById("meter");
const alertBox = document.getElementById("alert");
const result = document.getElementById("result");
const tips = document.getElementById("tips");

document.getElementById("toggle").addEventListener("change", e => {
  pw.type = e.target.checked ? "text" : "password";
});

function render(level, label) {
  meter.className = "meter " + label.toLowerCase().replace(" ", "-");
  [...meter.children].forEach((s, i) => s.classList.toggle("on", i < level));
}

async function run() {
  tips.replaceChildren();
  result.className = "";
  alertBox.hidden = true;
  btn.disabled = true;
  try {
    const res = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pw.value }),
    });
    const data = await res.json();
    if (!res.ok) {
      render(0, "compromised");
      result.className = "error";
      result.textContent = data.error || "Something went wrong.";
      return;
    }
    render(data.level, data.label);
    alertBox.hidden = !data.leaked;
    result.textContent = data.leaked ? data.label : `${data.label} (estimated ${data.entropy} bits)`;
    data.feedback.forEach(t => {
      const li = document.createElement("li");
      li.textContent = t;          // textContent, never innerHTML
      tips.appendChild(li);
    });
  } catch {
    result.className = "error";
    result.textContent = "Could not reach the server. Try again.";
  } finally {
    btn.disabled = false;
  }
}

btn.addEventListener("click", run);
pw.addEventListener("keydown", e => { if (e.key === "Enter") run(); });
