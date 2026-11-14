import { randomBytes } from "node:crypto";

export interface Session {
    email: string;
    csrfToken: string;
}

const sessions = new Map<string, Session>();

export function newSessionId(): string {
    return randomBytes(16).toString("hex");
}

export function getSession(id: string): Session {
    let s = sessions.get(id);
    if (!s) {
        s = { email: "user@example.com", csrfToken: randomBytes(16).toString("hex") };
        sessions.set(id, s);
    }
    return s;
}
