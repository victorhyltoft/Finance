import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, pw_validate

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    userID = session.get("user_id") # Get cookie 
    # Get user's cash
    cash = db.execute("SELECT cash FROM users WHERE id = :userID", userID=userID)
    cash = cash[0]["cash"]
    total = cash
    
    # Get user's portfolio (stocks)
    portfolio = db.execute("SELECT symbol, name, SUM(shares) as shares FROM user_shares WHERE userID = ? GROUP BY symbol HAVING NOT SUM(shares) <= 0", userID)
    # If portfolio (stocks) is empty
    if not portfolio:
        return render_template("index.html", cash=cash, portfolio=portfolio, total=total)

    stocks = []
    for row in range(len(portfolio)):
        stocks.append(lookup(portfolio[row]["symbol"]))
        total += (stocks[row]["price"] * portfolio[row]["shares"])

    return render_template("index.html", portfolio=portfolio, cash=cash, stock=stocks, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("Must provide symbol", 403)

        # Ensure number was submitted
        if not request.form.get("shares") or shares <= 0:
            return apology("Must provide shares", 403)
            
        shares = int(request.form.get("shares"))
        if shares <= 0:
            return apology("Must provide shares", 403)


        # Ensure the symbol is correct
        stock = lookup(request.form.get("symbol"))
        if stock == None:
            return apology("Invalid symbol", 403)

        # Ensure sufficient funds
        userID = session.get("user_id")
        rows = db.execute("SELECT * FROM users WHERE id = :id", id=userID)
        if (stock["price"] * shares) > rows[0]["cash"]:
            return apology("Insufficient funds", 405)
        # Remove funds from user
        db.execute("UPDATE users SET cash = ((SELECT cash FROM users WHERE id = ?) - ?) WHERE id = ?", userID, (stock["price"] * shares), userID)
            
        # Add shares to the user's portfolio
        db.execute("INSERT INTO user_shares (userID, symbol, name, shares, price) VALUES (?, ?, ?, ?, ?)", userID, stock["symbol"], stock["name"], shares, stock["price"])
        flash("Bought!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history(): # TODO 
    """Show history of transactions"""
    # Get cookie
    userID = session.get("user_id")

    # Get user's portfolio
    portfolio = db.execute("SELECT * FROM user_shares WHERE userID = ?", userID)

    return render_template("history.html", portfolio=portfolio)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("You were successfully logged in")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("Must provide symbol", 403)

        # Ensure the symbol is correct
        stock = lookup(request.form.get("symbol"))
        if stock == None:
            return apology("Invalid symbol", 403)

        return render_template("quoted.html", stock=stock)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register(): 
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("new_password")
        confirm = request.form.get("confirmation")
        
        # Validate password
        if not pw_validate(password):
            return apology("Password must contain a letter and a number", 403)

        # Ensure password and confirmation is the same
        if not password == confirm:
            return apology("Passwords didn't match", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) == 1:
            return apology("Username is taken", 405)

        # Hash password
        password_hashed = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)

        # Insert username and hashed password into the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hashed)

        # Remember which user has logged in
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash(f"Welcome {username}")
        return redirect("/")
    
    # User reached route via GET (as by accessing a link)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            flash("Must provide symbol", category="error")
            return redirect(url_for("sell"))

        # Ensure number was submitted
        shares = int(request.form.get("shares"))
        if not request.form.get("shares") or shares <= 0:
            flash("Must provide shares", category="error")
            return redirect(url_for("sell"))

        # Get the user's portfolio
        userID = session.get("user_id")
        
        # Lookup info about the stock
        stock = lookup(request.form.get("symbol"))

        # Ensure enough shares
        portfolio = db.execute("SELECT SUM(shares) as shares FROM user_shares WHERE userID = ? AND symbol = ?", userID, request.form.get("symbol"))
        if portfolio[0]["shares"] < shares:
            flash("Too many shares", category="error")
            return redirect(url_for("sell"))

        # Add transaction in user_shares
        ID = db.execute("INSERT INTO user_shares (userID, symbol, name, shares, price) VALUES (?, ?, ?, ?, ?)", userID, stock["symbol"], stock["name"], -shares, stock["price"])
        print(ID)

        # Add funds to user's cash depository 
        db.execute("UPDATE users SET cash = ((SELECT cash FROM users WHERE id = ?) + ?) WHERE id = ?", userID, shares * stock["price"], userID)
        flash("Sold!")
        return redirect("/")

    else:
        # Get cookie
        userID = session.get("user_id")
        
        # Get user's portfolio
        portfolio = db.execute("SELECT symbol, SUM(shares) as shares FROM user_shares WHERE userID = ? GROUP BY symbol HAVING NOT SUM(shares) <= 0", userID)
        
        return render_template("sell.html", portfolio=portfolio)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        
        # Check all fields are filled out
        cur = request.form.get("cur_pass")
        new = request.form.get("new_pass")
        confirm = request.form.get("confirmation")
        if not cur or not new or not confirm:
            flash("You must fill out every field")
            return redirect(url_for("account"))

        # Get cookie
        userID = session.get("user_id")
        
        # Get user data
        old_hash = db.execute("SELECT hash FROM users WHERE id = ?", userID)

        # Check for correct current password
        if not check_password_hash(old_hash[0]["hash"], cur):
            flash("Current password is wrong")
            return redirect(url_for("account"))

        # Validate password
        if not pw_validate(new):
            return apology("Password must contain a letter and a number", 403)

        # Check new password and confirmation matches
        if not new == confirm:
            flash("New password didn't match confirmation")
            return redirect(url_for("account"))

        # Update password
        # Hash password
        password_hashed = generate_password_hash(new, method="pbkdf2:sha256", salt_length=8)

        # Update the user's password (hashed)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", password_hashed, userID)
        flash("Password updated")
        return redirect("/")
    else:
        userID = session.get("user_id")
        username = db.execute("SELECT username FROM users WHERE id = ?", userID)
        return render_template("account.html", username=username)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

# TODO
# SQL Varchar of 255 for username - DONE
# SQL varchar for hashed password - DONE
# Implement a filter in history
# Implement at least 8 characters in password - DONE
# Implement at least a letter and number in password - DONE
# Allow users to sell their stock directly on index 
# Allow users to add cash