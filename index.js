import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import flash from "connect-flash";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 3600000, // 1 hour in milliseconds
    },
  })
);
app.use(flash());

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
});

db.connect();

const formatDateTime = (date) => {
  const options = {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  };
  return new Date(date).toLocaleDateString("en-GB", options);
};

// Middleware to protect routes
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
};

app.get("/signup", (req, res) => {
  res.render("signup.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/", ensureAuthenticated, async (req, res) => {
  const total = await Total(req.user.id);
  res.render("dashboard.ejs", { total });
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/dashboard",
  passport.authenticate("google", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.session.destroy((err) => {
      if (err) {
        return next(err);
      }
      res.redirect("/login");
    });
  });
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

app.post("/signin", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error("Login error:", err);
              return res.redirect("/login");
            }
            res.redirect("/");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
    res.redirect("/login");
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/dashboard",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (error) {
        return cb(error);
      }
    }
  )
);

app.get("/totalIncome", ensureAuthenticated, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT SUM(amount) FROM INCOME WHERE user_id = $1",
      [req.user.id]
    );
    const totalIncome = result.rows[0].sum || 0;
    res.json({ totalIncome });
  } catch (err) {
    console.error("Error fetching total income:", err);
    res.status(500).json({ error: "Error fetching total income" });
  }
});

app.get('/monthlyData', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.user.id;
    const currentMonthStart = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().split("T")[0];
    const nextMonthStart = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1).toISOString().split("T")[0];

    const incomeResult = await db.query(
      "SELECT SUM(amount) AS income FROM INCOME WHERE user_id = $1 AND income_date >= $2 AND income_date < $3",
      [userId, currentMonthStart, nextMonthStart]
    );
    const expenditureResult = await db.query(
      "SELECT SUM(amount) AS expenditure FROM EXPENSE WHERE user_id = $1 AND expense_date >= $2 AND expense_date < $3",
      [userId, currentMonthStart, nextMonthStart]
    );

    const income = incomeResult.rows[0].income || 0;
    const expenditure = expenditureResult.rows[0].expenditure || 0;
    const savings = income - expenditure;

    res.json({
      labels: [new Date().toLocaleString('default', { month: 'long' })],
      income: [income],
      expenditure: [expenditure],
      savings: [savings]
    });
  } catch (err) {
    console.error('Error fetching monthly data:', err);
    res.status(500).json({ error: 'Error fetching monthly data' });
  }
});



async function Total(userId) {
  const income = await db.query("SELECT SUM(amount) FROM INCOME WHERE user_id=$1",[userId]);
  const expense = await db.query("SELECT SUM(amount) FROM EXPENSE WHERE user_id=$1",[userId]);
  const currentMonthStart = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString().split("T")[0];
  const nextMonthStart = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 1).toISOString().split("T")[0];
  const budget = await db.query(
    "SELECT budget_amount FROM BUDGET WHERE budget_month >= $1 AND budget_month < $2 AND user_id=$3",
    [currentMonthStart, nextMonthStart,userId]
  );

  return {
    income: income.rows[0].sum,
    expense: expense.rows[0].sum,
    budget: budget.rows[0]?.budget_amount,
  };
}

app.post("/expense", ensureAuthenticated, async (req, res) => {
  const { category, amount, expense_date } = req.body;
  const userId = req.user.id;

  try {
    const total = await Total(req.user.id);
    const balance = total.income - total.expense;
    const parsedAmount = parseFloat(amount);

    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      req.flash('error', 'Amount cannot be zero or a negative number.');
      return res.redirect("/expense");
    }

    if (parsedAmount > balance) {
      req.flash('error', 'Amount exceeds balance.');
      return res.redirect("/expense");
    }

    const budget = total.budget || 0;
    if (parsedAmount > budget) {
      req.flash('warning', 'Amount exceeds budget.');
      res.render("expense-confirm.ejs", { category, amount, expense_date,total });
    } else {
      await db.query(
        "INSERT INTO EXPENSE (user_id, category, amount, expense_date) VALUES ($1, $2, $3, $4)",
        [userId, category, parsedAmount, expense_date]
      );
      res.redirect("/expenseTable");
    }
  } catch (err) {
    console.error('Error inserting expense data:', err);
    req.flash('error', 'Error inserting expense data.');
    res.redirect("/expense");
  }
});

app.post("/expense-confirm", ensureAuthenticated, async (req, res) => {
  const { category, amount, expense_date, confirmed } = req.body;
  const userId = req.user.id;

  if (confirmed === "yes") {
    try {
      await db.query(
        "INSERT INTO EXPENSE (user_id, category, amount, expense_date) VALUES ($1, $2, $3, $4)",
        [userId, category, amount, expense_date]
      );
      res.redirect("/expenseTable");
    } catch (err) {
      console.error('Error inserting expense data:', err);
      req.flash('error', 'Error inserting expense data.');
      res.redirect("/expense");
    }
  } else {
    res.redirect("/expense");
  }
});



app.get("/income", ensureAuthenticated, async (req, res) => {
  const total = await Total(req.user.id);
  res.render("income.ejs", { total });
});

app.get("/expense", ensureAuthenticated, async (req, res) => {
  const total = await Total(req.user.id);
  res.render("expense.ejs", { total });
});

app.get("/expense-confirm", ensureAuthenticated, async (req, res) => {
  const total = await Total(req.user.id);
  res.render("expense-confirm.ejs", { total });
});

app.get("/budget", ensureAuthenticated, async (req, res) => {
  const total = await Total(req.user.id);
  res.render("budget.ejs", { total });
});

app.get("/incomeTable", ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const result = await db.query("SELECT * FROM INCOME WHERE user_id=$1 ORDER BY ID DESC",[userId]);
  const income = result.rows;
  const total = await Total(req.user.id);
  res.render("income-table.ejs", { income, total });
});

app.get("/expenseTable", ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const result = await db.query("SELECT * FROM EXPENSE  WHERE user_id=$1 ORDER BY ID DESC",[userId]);
  const expense = result.rows;
  const total = await Total(req.user.id);
  res.render("expense-table.ejs", { expense, total });
});

app.get("/budgetTable", ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const result = await db.query("SELECT * FROM BUDGET WHERE user_id=$1 ORDER BY ID DESC",[userId]);
  const budget = result.rows;
  const total = await Total(req.user.id);
  res.render("budget-details.ejs", { budget, total });
});

const date = new Date().getDay();``
app.post("/income", async (req, res) => {
  const { source, amount, income_date } = req.body;
  const userId = req.user.id;

  try {
    await db.query(
      "INSERT INTO income (user_id, source, amount,income_date) VALUES ($1, $2, $3,$4)",
      [userId, source, amount, formatDateTime(income_date)]
    );
    res.redirect("/incomeTable");
  } catch (err) {
    console.error("Error inserting income data:", err);
    res.redirect("/income");
  }
});

app.post("/expense", ensureAuthenticated, async (req, res) => {
  const { category, amount, expense_date } = req.body;
  const userId = req.user.id;

  try {
    const total = await Total(req.user.id);
    const balance = total.income - total.expense;

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      req.flash('error', 'Expense amount must be greater than zero.');
      return res.redirect("/expense");
    }

    if (parsedAmount > balance) {
      req.flash('error', 'Expense exceeds the balance, cannot be added.');
      return res.redirect("/expense");
    }

    await db.query(
      "INSERT INTO EXPENSE (user_id, category, amount, expense_date) VALUES ($1, $2, $3, $4)",
      [userId, category, parsedAmount, expense_date]
    );
    res.redirect("/expenseTable");
  } catch (err) {
    console.error('Error inserting expense data:', err);
    req.flash('error', 'Error inserting expense data.');
    res.redirect("/expense");
  }
});


app.post("/budget", async (req, res) => {
  const { budgetMonth, budgetAmount } = req.body;
  const userId = req.user.id;

  try {
    // Check if a budget entry already exists for the given month
    const existingBudget = await db.query(
      "SELECT * FROM budget WHERE user_id = $1 AND budget_month = $2",
      [userId, budgetMonth + "-01"]
    );

    if (existingBudget.rows.length > 0) {
      // Update the existing entry
      await db.query(
        "UPDATE budget SET budget_amount = $1 WHERE user_id = $2 AND budget_month = $3",
        [budgetAmount, userId, budgetMonth + "-01"]
      );
    } else {
      // Insert a new entry
      await db.query(
        "INSERT INTO budget (user_id, budget_month, budget_amount) VALUES ($1, $2, $3)",
        [userId, budgetMonth + "-01", budgetAmount]
      );
    }

    res.redirect("/budgetTable");
  } catch (err) {
    console.error("Error processing budget data:", err);
    res.redirect("/budget");
  }
});

app.post("/deleteExpense", ensureAuthenticated, async (req, res) => {
  const expenseId = req.body.expenseId;

  try {
    await db.query("DELETE FROM EXPENSE WHERE id = $1", [expenseId]);
    res.redirect("/expenseTable"); // Redirect to the updated expense table
  } catch (err) {
    console.error("Error deleting expense:", err);
    res.redirect("/expenseTable"); // Redirect to the expense table even if there's an error
  }
});

app.post("/deleteIncome", ensureAuthenticated, async (req, res) => {
  const incomeId = req.body.incomeId;

  try {
    await db.query("DELETE FROM INCOME WHERE id = $1", [incomeId]);
    res.redirect("/incomeTable"); // Redirect to the updated expense table
  } catch (err) {
    console.error("Error deleting expense:", err);
    res.redirect("/incomeTable"); // Redirect to the expense table even if there's an error
  }
});

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`app is listening at http://localhost:${port}`);
});
