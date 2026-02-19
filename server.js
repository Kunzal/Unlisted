// ═══════════════════════════════════════════════════════════════
// UNLISTED INDIA — MVP Backend Server
// Deploy to: Railway, Render, Fly.io, or any Node.js host
// Local: node server.js  (needs MongoDB running)
// ═══════════════════════════════════════════════════════════════
require("dotenv").config();
const express     = require("express");
const cors        = require("cors");
const helmet      = require("helmet");
const rateLimit   = require("express-rate-limit");
const mongoose    = require("mongoose");
const bcrypt      = require("bcryptjs");
const jwt         = require("jsonwebtoken");
const path        = require("path");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "unlisted-india-dev-secret-change-in-prod";

// ── Middleware ──────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
app.use("/api/", limiter);

// ── MongoDB Models ──────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/unlisted_india")
  .then(() => console.log("✅ MongoDB connected"))
  .catch(e => { console.error("❌ MongoDB error:", e.message); });

// Company schema
const SourceSchema = new mongoose.Schema({ n: String, b: Number, s: Number }, { _id: false });
const CompanySchema = new mongoose.Schema({
  name: String, fullName: String, sector: String, category: String,
  ipoStatus: String, isin: String, faceValue: Number, lotSize: Number,
  hi52: Number, lo52: Number, sources: [SourceSchema],
  peer: String, peerTick: String, peerPx: Number, desc: String,
  isActive: { type: Boolean, default: true },
}, { timestamps: true });
CompanySchema.index({ name: "text", fullName: "text", sector: "text" });
const Company = mongoose.model("Company", CompanySchema);

// User schema
const UserSchema = new mongoose.Schema({
  name: String, email: { type: String, unique: true, lowercase: true },
  password: { type: String, select: false },
  role: { type: String, default: "user" },
  watchlist: [{ type: mongoose.Schema.Types.ObjectId, ref: "Company" }],
}, { timestamps: true });
UserSchema.pre("save", async function(next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
const User = mongoose.model("User", UserSchema);

// OTC Inquiry schema
const InquirySchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: "Company" },
  companyName: String,
  type: { type: String, enum: ["buy", "sell"] },
  name: String,
  phone: String,
  quantity: Number,
  targetPrice: Number,
  message: String,
  status: { type: String, default: "pending" }, // pending, contacted, closed
}, { timestamps: true });
const Inquiry = mongoose.model("Inquiry", InquirySchema);

// ── Price computation ───────────────────────────────────────────
function computePrices(sources) {
  if (!sources || !sources.length) return {};
  const buys  = sources.map(s => s.b);
  const sells = sources.map(s => s.s);
  const avgBuy  = buys.reduce((a,b)=>a+b,0)/buys.length;
  const avgSell = sells.reduce((a,b)=>a+b,0)/sells.length;
  const bestBuy  = Math.min(...buys);
  const bestSell = Math.min(...sells);
  const midConsensus = Math.round((avgBuy + avgSell) / 2);
  return {
    bestBuy, bestSell, maxSell: Math.max(...sells),
    avgBuy: +avgBuy.toFixed(2), avgSell: +avgSell.toFixed(2),
    midConsensus,
    spread:   +((avgSell - avgBuy) / avgBuy * 100).toFixed(2),
    variance: +((Math.max(...buys) - Math.min(...buys)) / Math.min(...buys) * 100).toFixed(2),
    bestBuySource:  sources.find(s=>s.b===bestBuy)?.n,
    bestSellSource: sources.find(s=>s.s===bestSell)?.n,
  };
}

// ── Auth middleware ─────────────────────────────────────────────
const protect = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, message: "Not authenticated" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) return res.status(401).json({ success: false, message: "User not found" });
    next();
  } catch { res.status(401).json({ success: false, message: "Invalid token" }); }
};

const adminOnly = (req, res, next) => {
  if (req.user?.role !== "admin") return res.status(403).json({ success: false, message: "Admins only" });
  next();
};

// ── Response helpers ────────────────────────────────────────────
const ok   = (res, data, meta={}) => res.json({ success: true, data, meta, ts: new Date() });
const fail = (res, msg, code=400) => res.status(code).json({ success: false, message: msg });

// ══════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════

// Health
app.get("/health", (req,res) => res.json({ status:"ok", uptime: process.uptime() }));

// ── Companies ──────────────────────────────────────────────────
app.get("/api/v1/companies", async (req, res) => {
  const { search, category, sector, ipoStatus, sort="name", page=1, limit=50 } = req.query;
  const filter = { isActive: true };
  if (category)  filter.category  = category;
  if (sector)    filter.sector    = sector;
  if (ipoStatus) filter.ipoStatus = ipoStatus;
  if (search)    filter.$text     = { $search: search };

  let mongoSort = { name: 1 };
  if (sort === "buy_asc")  mongoSort = { "sources.0.b": 1 };
  if (sort === "buy_desc") mongoSort = { "sources.0.b": -1 };

  const [companies, total] = await Promise.all([
    Company.find(filter).sort(mongoSort).skip((page-1)*limit).limit(+limit),
    Company.countDocuments(filter),
  ]);

  let result = companies.map(c => {
    const d = c.toObject();
    d.computed = computePrices(d.sources);
    if (d.computed.midConsensus && d.peerPx) {
      const pct = +((((d.computed.midConsensus - d.peerPx) / d.peerPx) * 100).toFixed(2));
      d.computed.peer = { pct, direction: pct < 0 ? "discount" : "premium" };
    }
    return d;
  });

  if (sort === "spread") result.sort((a,b) => (b.computed.spread||0) - (a.computed.spread||0));

  ok(res, result, { total, page: +page, limit: +limit });
});

app.get("/api/v1/companies/stats", async (req, res) => {
  const [total, byCategory] = await Promise.all([
    Company.countDocuments({ isActive: true }),
    Company.aggregate([{ $match:{isActive:true} }, { $group:{_id:"$category", count:{$sum:1}} }]),
  ]);
  ok(res, { total, priceSources: 5, byCategory: Object.fromEntries(byCategory.map(c=>[c._id,c.count])) });
});

app.get("/api/v1/companies/ticker", async (req, res) => {
  const companies = await Company.find({ isActive: true }).select("name category sources");
  ok(res, companies.map(c => {
    const p = computePrices(c.sources);
    return { id: c._id, name: c.name, category: c.category, bestBuy: p.bestBuy, bestSell: p.bestSell };
  }));
});

app.get("/api/v1/companies/:id", async (req, res) => {
  const c = await Company.findById(req.params.id);
  if (!c || !c.isActive) return fail(res, "Not found", 404);
  const d = c.toObject();
  d.computed = computePrices(d.sources);
  if (d.computed.midConsensus && d.peerPx) {
    const pct = +((((d.computed.midConsensus - d.peerPx) / d.peerPx) * 100).toFixed(2));
    d.computed.peer = { pct, direction: pct < 0 ? "discount" : "premium" };
  }
  ok(res, d);
});

// Admin: create company
app.post("/api/v1/companies", protect, adminOnly, async (req, res) => {
  const c = await Company.create(req.body);
  ok(res, c);
});

// Admin: update prices
app.patch("/api/v1/companies/:id/prices", protect, adminOnly, async (req, res) => {
  const c = await Company.findByIdAndUpdate(req.params.id, { sources: req.body.sources }, { new: true });
  if (!c) return fail(res, "Not found", 404);
  const d = c.toObject(); d.computed = computePrices(d.sources);
  ok(res, d);
});

// Admin: update metadata
app.patch("/api/v1/companies/:id", protect, adminOnly, async (req, res) => {
  delete req.body.sources;
  const c = await Company.findByIdAndUpdate(req.params.id, req.body, { new: true });
  if (!c) return fail(res, "Not found", 404);
  ok(res, c);
});

// Admin: delete
app.delete("/api/v1/companies/:id", protect, adminOnly, async (req, res) => {
  await Company.findByIdAndUpdate(req.params.id, { isActive: false });
  ok(res, null);
});

// ── Auth ───────────────────────────────────────────────────────
app.post("/api/v1/auth/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return fail(res, "All fields required");
  if (await User.findOne({ email })) return fail(res, "Email already registered", 409);
  const user  = await User.create({ name, email, password });
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
  ok(res, { token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
});

app.post("/api/v1/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email }).select("+password");
  if (!user || !(await bcrypt.compare(password, user.password)))
    return fail(res, "Invalid credentials", 401);
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
  ok(res, { token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
});

app.get("/api/v1/auth/me", protect, async (req, res) => {
  const user = await User.findById(req.user._id).populate("watchlist","name sector category");
  ok(res, user);
});

// ── Watchlist ──────────────────────────────────────────────────
app.get("/api/v1/watchlist", protect, async (req, res) => {
  const user = await User.findById(req.user._id).populate("watchlist");
  ok(res, (user.watchlist||[]).map(c => {
    const d = c.toObject(); d.computed = computePrices(d.sources); return d;
  }));
});

app.post("/api/v1/watchlist/:id", protect, async (req, res) => {
  await User.findByIdAndUpdate(req.user._id, { $addToSet: { watchlist: req.params.id } });
  ok(res, null);
});

app.delete("/api/v1/watchlist/:id", protect, async (req, res) => {
  await User.findByIdAndUpdate(req.user._id, { $pull: { watchlist: req.params.id } });
  ok(res, null);
});

// ── OTC Inquiries (Buy/Sell) ───────────────────────────────────
app.post("/api/v1/inquiries", async (req, res) => {
  const { companyId, companyName, type, name, phone, quantity, targetPrice, message } = req.body;
  if (!phone || !name || !type) return fail(res, "Name, phone and type are required");
  const inquiry = await Inquiry.create({ companyId, companyName, type, name, phone, quantity, targetPrice, message });
  ok(res, inquiry);
});

// Admin: list inquiries
app.get("/api/v1/inquiries", protect, adminOnly, async (req, res) => {
  const inquiries = await Inquiry.find().sort({ createdAt: -1 }).populate("companyId","name");
  ok(res, inquiries, { total: inquiries.length });
});

// Admin: update inquiry status
app.patch("/api/v1/inquiries/:id", protect, adminOnly, async (req, res) => {
  const inq = await Inquiry.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
  ok(res, inq);
});

// Admin stats
app.get("/api/v1/admin/stats", protect, adminOnly, async (req, res) => {
  const [users, companies, inquiries] = await Promise.all([
    User.countDocuments(), Company.countDocuments({ isActive: true }), Inquiry.countDocuments(),
  ]);
  ok(res, { users, companies, inquiries });
});

// ── SPA fallback ───────────────────────────────────────────────
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ── Error handler ───────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: err.message });
});

// ── Seed data on first run ──────────────────────────────────────
async function seedIfEmpty() {
  const count = await Company.countDocuments();
  if (count > 0) return;

  console.log("🌱 Seeding companies...");
  await Company.insertMany(SEED_DATA);

  const adminExists = await User.findOne({ email: "admin@unlisted.in" });
  if (!adminExists) {
    await User.create({ name:"Admin", email:"admin@unlisted.in", password:"Admin@12345", role:"admin" });
    console.log("👤 Admin: admin@unlisted.in / Admin@12345");
  }
  console.log("✅ Seed complete");
}

// ── Start ───────────────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`🚀 Unlisted India API → http://localhost:${PORT}`);
  await seedIfEmpty();
});

// ── Seed Data ───────────────────────────────────────────────────
const SEED_DATA = [
  { name:"NSE India", fullName:"National Stock Exchange of India Ltd", sector:"Financial Infra", category:"Pre-IPO", ipoStatus:"Filed DRHP", isin:"INE742F01042", faceValue:1, lotSize:10, hi52:2470, lo52:1650, sources:[{n:"Planify",b:2080,s:2100},{n:"SharesCart",b:2065,s:2085},{n:"Altius",b:2050,s:2090},{n:"WWIPL",b:2055,s:2095},{n:"UnlistedZone",b:2070,s:2100}], peer:"BSE Ltd", peerTick:"BSE", peerPx:5480, desc:"India's largest stock exchange by turnover. Rothschild appointed as IPO advisor. DRHP under SEBI review." },
  { name:"Hero FinCorp", fullName:"Hero FinCorp Limited", sector:"NBFC", category:"Pre-IPO", ipoStatus:"SEBI Approved", isin:"INE980H01014", faceValue:10, lotSize:50, hi52:2200, lo52:1100, sources:[{n:"Planify",b:1160,s:1180},{n:"SharesCart",b:1115,s:1135},{n:"Altius",b:1100,s:1140},{n:"WWIPL",b:1095,s:1145},{n:"UnlistedZone",b:1110,s:1150}], peer:"Bajaj Finance", peerTick:"BAJFINANCE", peerPx:8560, desc:"NBFC arm of Hero MotoCorp. SEBI IPO observation letter received. AUM ₹50,925 Cr." },
  { name:"SBI Mutual Fund", fullName:"SBI Funds Management Ltd", sector:"Asset Mgmt", category:"Pre-IPO", ipoStatus:"IPO Expected 2026", isin:"INE003J01013", faceValue:10, lotSize:50, hi52:2900, lo52:720, sources:[{n:"Planify",b:775,s:800},{n:"SharesCart",b:768,s:785},{n:"Altius",b:770,s:790},{n:"WWIPL",b:760,s:795},{n:"UnlistedZone",b:772,s:792}], peer:"HDFC AMC", peerTick:"HDFCAMC", peerPx:4380, desc:"India's largest AMC by AUM. SBI subsidiary. 10% equity dilution IPO expected 2026." },
  { name:"NSDL", fullName:"National Securities Depository Ltd", sector:"Financial Infra", category:"Pre-IPO", ipoStatus:"SEBI Lapsed", isin:"INE092T01019", faceValue:10, lotSize:50, hi52:1300, lo52:900, sources:[{n:"Planify",b:1058,s:1072},{n:"SharesCart",b:1040,s:1060},{n:"Altius",b:1035,s:1065},{n:"WWIPL",b:1025,s:1055},{n:"UnlistedZone",b:1045,s:1068}], peer:"CDSL", peerTick:"CDSL", peerPx:1480, desc:"India's largest depository. SEBI approval lapsed July 2025. Reapplication pending." },
  { name:"PhonePe", fullName:"PhonePe Private Limited", sector:"Fintech", category:"Startup", ipoStatus:"DRHP Filed", isin:"—", faceValue:1, lotSize:25, hi52:5500, lo52:3200, sources:[{n:"Planify",b:4350,s:4550},{n:"SharesCart",b:4200,s:4400},{n:"Altius",b:4300,s:4500},{n:"WWIPL",b:4250,s:4450},{n:"UnlistedZone",b:4280,s:4480}], peer:"Paytm", peerTick:"PAYTM", peerPx:830, desc:"India's #1 UPI app. Walmart-backed. Confidential DRHP with SEBI. $13–15B IPO targeting H2 2026." },
  { name:"Zepto", fullName:"Kiranakart Technologies Pvt Ltd", sector:"Quick Commerce", category:"Startup", ipoStatus:"DRHP Filed", isin:"—", faceValue:5, lotSize:500, hi52:2750, lo52:49, sources:[{n:"Planify",b:56,s:62},{n:"SharesCart",b:55,s:61},{n:"Altius",b:57,s:63},{n:"WWIPL",b:55,s:60},{n:"UnlistedZone",b:58,s:64}], peer:"Zomato", peerTick:"ZOMATO", peerPx:225, desc:"India's leading q-commerce platform. 1,000+ dark stores, 70+ cities. ₹11,000 Cr IPO filed." },
  { name:"OYO", fullName:"Oravel Stays Ltd", sector:"Hospitality", category:"Startup", ipoStatus:"IPO Planned", isin:"—", faceValue:1, lotSize:500, hi52:65, lo52:18, sources:[{n:"Planify",b:25,s:28},{n:"SharesCart",b:25,s:28},{n:"Altius",b:25,s:29},{n:"WWIPL",b:24,s:27},{n:"UnlistedZone",b:26,s:29}], peer:"Indian Hotels", peerTick:"INDHOTEL", peerPx:680, desc:"Global hospitality platform seeking shareholder approval for ₹6,650 Cr IPO." },
  { name:"Capgemini India", fullName:"Capgemini Technology Services India Ltd", sector:"IT Services", category:"MNC Subsidiary", ipoStatus:"No IPO", isin:"INE879A01012", faceValue:10, lotSize:10, hi52:14000, lo52:9500, sources:[{n:"Planify",b:11000,s:11250},{n:"SharesCart",b:10800,s:11200},{n:"Altius",b:10900,s:11100},{n:"WWIPL",b:10750,s:11000},{n:"UnlistedZone",b:10850,s:11150}], peer:"Infosys", peerTick:"INFY", peerPx:1630, desc:"Indian arm of French IT giant. Consistently profitable. MNC subsidiary — no IPO expected." },
  { name:"HDFC Securities", fullName:"HDFC Securities Limited", sector:"Stock Broking", category:"Pre-IPO", ipoStatus:"Rumoured", isin:"INE768C01010", faceValue:10, lotSize:10, hi52:10500, lo52:7800, sources:[{n:"Planify",b:9200,s:9500},{n:"SharesCart",b:9100,s:9400},{n:"Altius",b:9200,s:9400},{n:"WWIPL",b:9050,s:9350},{n:"UnlistedZone",b:9150,s:9450}], peer:"Angel One", peerTick:"ANGELONE", peerPx:2150, desc:"Subsidiary of HDFC Bank. Potential carve-out / IPO as HDFC Bank explores strategic options." },
  { name:"CSK", fullName:"Chennai Super Kings Cricket Ltd", sector:"Sports Franchise", category:"Sports", ipoStatus:"No IPO", isin:"INE971H01012", faceValue:1, lotSize:100, hi52:280, lo52:140, sources:[{n:"Planify",b:255,s:268},{n:"SharesCart",b:255,s:265},{n:"Altius",b:250,s:262},{n:"WWIPL",b:248,s:260},{n:"UnlistedZone",b:252,s:264}], peer:null, peerTick:null, peerPx:null, desc:"India's most popular IPL franchise. Unique alternative asset class." },
  { name:"NCDEX", fullName:"National Commodity & Derivatives Exchange", sector:"Financial Infra", category:"Pre-IPO", ipoStatus:"Exploring", isin:"INE274G01010", faceValue:10, lotSize:100, hi52:560, lo52:340, sources:[{n:"Planify",b:448,s:462},{n:"SharesCart",b:442,s:455},{n:"Altius",b:440,s:458},{n:"WWIPL",b:438,s:450},{n:"UnlistedZone",b:445,s:460}], peer:"MCX", peerTick:"MCX", peerPx:5150, desc:"India's leading agri commodity exchange. TCS as tech partner." },
  { name:"boAt", fullName:"Imagine Marketing Ltd", sector:"Consumer Electronics", category:"Startup", ipoStatus:"DRHP Filed", isin:"—", faceValue:5, lotSize:100, hi52:1600, lo52:900, sources:[{n:"Planify",b:1120,s:1220},{n:"SharesCart",b:1100,s:1200},{n:"Altius",b:1080,s:1180},{n:"WWIPL",b:1090,s:1190},{n:"UnlistedZone",b:1100,s:1200}], peer:"Dixon Technologies", peerTick:"DIXON", peerPx:15800, desc:"India's #1 audio & wearables brand. ₹1,500 Cr IPO filed." },
  { name:"Orbis Financial", fullName:"Orbis Financial Corporation Ltd", sector:"Financial Services", category:"Pre-IPO", ipoStatus:"Exploring", isin:"INE450Q01019", faceValue:10, lotSize:100, hi52:720, lo52:390, sources:[{n:"Planify",b:465,s:505},{n:"SharesCart",b:460,s:500},{n:"Altius",b:455,s:495},{n:"WWIPL",b:452,s:492},{n:"UnlistedZone",b:458,s:498}], peer:"CDSL", peerTick:"CDSL", peerPx:1480, desc:"Custodial & depository services. Steady earnings growth." },
];
