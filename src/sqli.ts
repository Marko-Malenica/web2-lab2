import { DatabaseSync } from "node:sqlite";

export interface Message {
    id: number;
    message: string;
    pin: string;
}

const db = new DatabaseSync(":memory:");
db.exec(
    "CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, message TEXT NOT NULL, pin TEXT NOT NULL)"
);
db.prepare("INSERT INTO messages (message, pin) VALUES (?, ?)").run("admin", "9999");

function toMessage(row: unknown): Message {
    const r = row as Record<string, unknown>;
    return { id: Number(r["id"]), message: String(r["message"]), pin: String(r["pin"]) };
}

export function saveMessage(message: string, pin: string): void {
    db.prepare("INSERT INTO messages (message, pin) VALUES (?, ?)").run(message, pin);
}

export function getMessages(input: string, vulnerable: boolean): Message[] {
    if (vulnerable) {
        const query = `SELECT id, message, pin FROM messages WHERE message = '${input}'`;
        return db.prepare(query).all().map(toMessage);
    }
    return db
        .prepare("SELECT id, message, pin FROM messages WHERE message = ?")
        .all(input)
        .map(toMessage);
}
