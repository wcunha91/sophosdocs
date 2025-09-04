// server/index.mjs
import express from "express";
import cors from "cors";
import { sophosCollect } from "./sophos-collect.mjs";

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());            // ajuste origins se quiser restringir
app.use(express.json({ limit: "10mb" }));

app.post("/api/sophos-collect", async (req, res) => {
  try {
    const data = await sophosCollect(req.body);
    res.json(data);
  } catch (e) {
    res.status(400).json({ error: String(e?.message ?? e) });
  }
});

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`[api] rodando em http://localhost:${PORT}`);
});
