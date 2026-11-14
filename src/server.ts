import express, { type Request, type Response } from "express";
import cookieParser from "cookie-parser";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getMessages, saveMessage, type Message } from "./sqli";
import { getSession, newSessionId, type Session } from "./csrf";

const template = readFileSync(join(__dirname, "..", "public", "index.html"), "utf8");

function escapeHtml(text: string): string {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function renderResults(results: Message[] | null): string {
    if (results === null) return "";
    if (results.length === 0) return "<p>Nema rezultata.</p>";
    const rows = results
        .map((r) => `<tr><td>${r.id}</td><td>${escapeHtml(r.message)}</td><td>${escapeHtml(r.pin)}</td></tr>`)
        .join("");
    return `<table border="1" cellpadding="4"><tr><th>id</th><th>message</th><th>pin</th></tr>${rows}</table>`;
}

function renderPage(
    sqliVulnerable: boolean,
    csrfVulnerable: boolean,
    results: Message[] | null,
    lastInput: string,
    session: Session
): string {
    return template
        .replace("%%SQLI_CHECKED%%", sqliVulnerable ? "checked" : "")
        .replace("%%CSRF_CHECKED%%", csrfVulnerable ? "checked" : "")
        .replace("%%LAST_INPUT%%", escapeHtml(lastInput))
        .replace("%%RESULTS%%", renderResults(results))
        .replace("%%EMAIL%%", escapeHtml(session.email))
        .replace("%%TOKEN%%", escapeHtml(session.csrfToken));
}

const PORT = Number(process.env["PORT"] ?? 3000);
const COOKIE_NAME = "lab2_sid";

let sqliVulnerable = true;
let csrfVulnerable = true;

const app = express();
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

function ensureSession(req: Request, res: Response): string {
    const existing = req.cookies[COOKIE_NAME] as string | undefined;
    if (existing) return existing;
    const id = newSessionId();
    res.cookie(COOKIE_NAME, id, { httpOnly: true, sameSite: "none", secure: req.secure });
    return id;
}

app.get("/", (req: Request, res: Response) => {
    const id = ensureSession(req, res);
    res.type("html").send(renderPage(sqliVulnerable, csrfVulnerable, null, "", getSession(id)));
});

app.post("/sqli-toggle", (req: Request, res: Response) => {
    sqliVulnerable = req.body["vulnerable"] === "on";
    res.redirect("/");
});

app.post("/csrf-toggle", (req: Request, res: Response) => {
    csrfVulnerable = req.body["vulnerable"] === "on";
    res.redirect("/");
});

app.post("/message", (req: Request, res: Response) => {
    const id = ensureSession(req, res);
    const message = String(req.body["message"] ?? "");
    const pin = String(req.body["pin"] ?? "");

    if (message.length > 0 && pin.length > 0) {
        saveMessage(message, pin);
    }

    const results = getMessages(message, sqliVulnerable);
    res.type("html").send(renderPage(sqliVulnerable, csrfVulnerable, results, message, getSession(id)));
});

app.get("/set-email", (req: Request, res: Response) => {
    const id = req.cookies[COOKIE_NAME] as string | undefined;
    if (!id) {
        res.status(400).send("No session.");
        return;
    }

    const session = getSession(id);
    const newEmail = String(req.query["email"] ?? "");
    if (newEmail.length === 0) {
        res.status(400).send("Missing email.");
        return;
    }

    if (!csrfVulnerable && req.query["token"] !== session.csrfToken) {
        res.status(403).send("Request rejected: missing valid CSRF token.");
        return;
    }

    session.email = newEmail;
    res.status(204).send();
});

app.listen(PORT, () => {
    console.log(`Lab 2 app listening on port ${PORT}`);
});
