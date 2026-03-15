const fixturePath = "./fixtures/authorized_fixture.json";
const requiredHeaders = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options"
];

function riskScoreFor(target) {
  let score = 0;
  const headers = Object.keys(target.headers || {}).map((header) => header.toLowerCase());
  requiredHeaders.forEach((header) => {
    if (!headers.includes(header)) {
      score += 1;
    }
  });
  (target.exposures || []).forEach((exposure) => {
    if (exposure.severity === "high") {
      score += 3;
    } else if (exposure.severity === "medium") {
      score += 2;
    } else {
      score += 1;
    }
  });
  return score;
}

function riskLevel(score) {
  if (score >= 5) {
    return "high";
  }
  if (score >= 3) {
    return "medium";
  }
  return "low";
}

function missingHeaders(target) {
  const headers = Object.keys(target.headers || {}).map((header) => header.toLowerCase());
  return requiredHeaders.filter((header) => !headers.includes(header));
}

function renderTarget(target) {
  const score = riskScoreFor(target);
  const level = riskLevel(score);
  const issues = [
    ...missingHeaders(target).map((header) => `Missing ${header}`),
    ...(target.exposures || []).map((exposure) => exposure.detail)
  ];

  return `
    <article class="target-card">
      <div class="target-head">
        <div>
          <p class="eyebrow">${target.url}</p>
          <h2>${target.title}</h2>
        </div>
        <span class="risk-chip risk-${level}">${level.toUpperCase()}</span>
      </div>
      <p>${target.notes}</p>
      <div class="tech-row">
        ${(target.technologies || []).map((tech) => `<span>${tech}</span>`).join("")}
      </div>
      <ul class="issue-list">
        ${issues.map((issue) => `<li><strong>Signal</strong> ${issue}</li>`).join("")}
      </ul>
    </article>
  `;
}

async function init() {
  const response = await fetch(fixturePath);
  const targets = await response.json();
  const grid = document.getElementById("target-grid");
  const headerGapCount = targets.reduce((count, target) => count + missingHeaders(target).length, 0);
  const highRiskCount = targets.filter((target) => riskLevel(riskScoreFor(target)) !== "low").length;

  document.getElementById("target-count").textContent = `${targets.length}`;
  document.getElementById("high-risk-count").textContent = `${highRiskCount}`;
  document.getElementById("header-gap-count").textContent = `${headerGapCount}`;
  grid.innerHTML = targets.map(renderTarget).join("");
}

init().catch((error) => {
  const grid = document.getElementById("target-grid");
  grid.innerHTML = `<article class="target-card"><h2>Could not load fixture data</h2><p>${error}</p></article>`;
});
