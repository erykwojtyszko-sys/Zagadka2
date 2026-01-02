export async function onRequest(context) {
  const { request } = context;

  // GET: zwróć aktualną podpowiedź (bez zmiany etapu)
  if (request.method === "GET") {
    return handle(context, "", "");
  }

  // POST: sprawdzanie odpowiedzi
  if (request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const answerRaw = (body.answer ?? "").toString();
    const token = (body.token ?? "").toString();
    return handle(context, answerRaw, token);
  }

  return new Response("Method Not Allowed", { status: 405 });
}

async function handle(context, answerRaw, token) {
  const { env } = context;

  // === TU MASZ ZAGADKI I ODPOWIEDZI ===
  const steps = [
    {
      clue: `Na tym opiera się zagadka
I każdy ma swoją
To koncept nie byle łatka
Niektórzy się jej boją`,
      answer: "tajemnica",
    },
    {
      clue: `Bardzo dobrze,
Początek przykrótki jak pewna osoba
Nikt nie zobaczy bo prędko się schowa
Mleko popsuje, w ogródku postoi
Michała ktoś od tej postaci zgnoji`,
      answer: "krasnal",
    },
    {
      clue: `XD
Będzie przy tobie gdy czas się zatrzyma
Będzie też gdy nikt inny nie wytrzyma
Pomaga wymyślić najróżniejsze pomysły
Bez niej w szarym świecie stracilibysmy zmysły
Dzieci na codzień się nią chwalą 
A starzy z jej braku często się żalą`,
      answer: "wyobraźnia",
    },
    {
      clue: `Pzdr
Trzeba inaczej na to spojrzeć
Rzucić koncept lepiej dojrzeć
Ewidętnie będzie to dla was progiem
Środek znaleźć? a może bokiem?
Ćma do światła, rzuć na to okiem`,
      answer: "treść",
    },
    {
      clue: `Jeśli to ogarnałeś sam, goated:
Trochę prościej, czasem kzywo
Czasem bez mycia pachnie rybą`,
      answer: "siusiak",
    },
    {
      clue: `idziesz jak przez błoto
,jacyś głupcy się nabierali
bo zamiast złota to sprzedawali
wmawiają że przynosi wszystkim bogactwa
a kiedyś jego fałszywość niszczyła hrabstwa`,
      answer: "piryt",
    },
    {
      clue: `Nad głową wisi, choć nie ma haka
Czasem jak wata, czasem jak szmata
Z deszczem przychodzi lub znika w sekundę
Zmienia kształt, formę i swoją rundę
Dzieci w niej widzą smoki i góry
A informatyk trzyma tam… dane z natury`,
      answer: "chmura",
    },
    {
      clue: `Więc?
Dlaczego to wysztko robiłem?
W tym VS się kodem bawiłem
Zajżyj mi do głowy, zobacz odpowiedź
Domyśl się co ma na celu ta spowiedź
Dla niektórych prostę, dla innych nię
I tak odpowiedź zaskoczy cię`,
      answer: "nuda",
    },
  ];
  // ============================

  const SECRET = env.TOKEN_SECRET;
  if (!SECRET) return json({ error: "Brak TOKEN_SECRET po stronie serwera." }, 500);

  // Normalizacja: spacje, wielkość liter, polskie znaki
  const normalize = (s) =>
    s.trim().toLowerCase().normalize("NFD").replace(/\p{Diacritic}/gu, "");

  const enc = new TextEncoder();

  // base64url (dla podpisu)
  const b64u = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

  const fromB64u = (str) => {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  };

  async function hmacSign(msg) {
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    return crypto.subtle.sign("HMAC", key, enc.encode(msg));
  }

  async function makeToken(stepIndex) {
    const payload = JSON.stringify({ i: stepIndex });
    const payloadB64 = btoa(payload).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const sig = await hmacSign(payloadB64);
    return payloadB64 + "." + b64u(sig);
  }

  async function readToken(tok) {
    if (!tok || !tok.includes(".")) return 0;
    const [payloadB64, sigB64] = tok.split(".");
    const expected = await hmacSign(payloadB64);
    const got = fromB64u(sigB64);
    const exp = new Uint8Array(expected);
    if (got.length !== exp.length) return 0;

    // stałoczasowe porównanie
    let diff = 0;
    for (let i = 0; i < got.length; i++) diff |= got[i] ^ exp[i];
    if (diff !== 0) return 0;

    const payloadJson = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
    const payload = JSON.parse(payloadJson);
    const idx = Number(payload.i);
    return Number.isFinite(idx) && idx >= 0 ? idx : 0;
  }

  const currentIndex = await readToken(token);

  // Jeśli pusto → zwróć aktualną clue
  if (!normalize(answerRaw)) {
    const clue = steps[Math.min(currentIndex, steps.length - 1)].clue;
    const newToken = await makeToken(currentIndex);
    return json({ clue, token: newToken, done: currentIndex >= steps.length - 1 });
  }

  const expected = steps[currentIndex]?.answer;
  if (expected == null) return json({ error: "Nieznany etap." }, 400);

  if (normalize(answerRaw) !== normalize(expected)) {
    const clue = steps[currentIndex].clue;
    const sameToken = await makeToken(currentIndex);
    return json({ error: "Zła odpowiedź.", clue, token: sameToken }, 401);
  }

  const nextIndex = Math.min(currentIndex + 1, steps.length - 1);
  const clue = steps[nextIndex].clue;
  const newToken = await makeToken(nextIndex);
  const done = nextIndex >= steps.length - 1;

  return json({ clue, token: newToken, done });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}
