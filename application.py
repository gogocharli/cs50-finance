import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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

    # List the available stocks for the user
    stocks = db.execute(
        "SELECT symbol, shares FROM stocks WHERE user_id = :id", id=session["user_id"]
    )

    stockList = []
    stockTotal = 0

    # Create an object for each owned stock
    for stock in stocks:
        stockInfo = lookup(stock["symbol"])
        total = stock["shares"] * stockInfo["price"]

        stockList.append(
            {
                "symbol": stock["symbol"],
                "name": stockInfo["name"],
                "shares": stock["shares"],
                "currentPrice": stockInfo["price"],
                "total": total,
            }
        )

        # Increment the total amount owned
        stockTotal += total

    # Calculate cash and total balance
    userInfo = db.execute(
        "SELECT cash FROM users WHERE id = :id", id=session["user_id"]
    )

    cash = userInfo[0]["cash"]
    balance = cash + stockTotal

    return render_template(
        "index.html", stockList=stockList, cash=cash, balance=balance
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    type = "BUY"

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Ensure that both fields are valid
        if not symbol:
            return apology("must provide symbol", 403)
        elif not shares:
            return apology("must provide number of shares", 403)
        elif int(shares) < 1:
            return apology("number of shares must be greater than 1", 403)

        # Lookup the specified share price
        stockInfo = lookup(symbol)

        # Verify it exists in the iex database
        if not stockInfo:
            return apology(f"could not find price information about {symbol}", 404)

        # Calculate the price of the transaction
        cost = int(stockInfo["price"]) * int(shares)

        # Make sure the user has enough for the transaction
        rows = db.execute(
            "SELECT cash FROM users WHERE id = :id", id=session["user_id"]
        )
        liquidity = int(rows[0]["cash"])

        if liquidity >= cost:
            # Write down the transaction inside the transactions table
            db.execute(
                "INSERT INTO transactions (type, symbol, shares, price) VALUES (:type, :symbol, :shares, :price)",
                type=type,
                symbol=symbol,
                shares=shares,
                price=int(stockInfo["price"]),
            )

            # Register the last transaction in the trades table and associate it with the user id
            lastTransaction = db.execute(
                "SELECT id FROM transactions ORDER BY id DESC LIMIT 1"
            )

            db.execute(
                "INSERT INTO trades (trade_id, user_id) VALUES (:transaction, :user)",
                transaction=lastTransaction[0]["id"],
                user=session["user_id"],
            )

            # Update the current stocks of the user in the stocks table
            trades = db.execute(
                "SELECT symbol FROM stocks WHERE symbol = :symbol AND user_id = :id",
                symbol=symbol,
                id=session["user_id"],
            )

            # If the symbol is not there, create it and add the number of shares
            if len(trades) == 0:
                db.execute(
                    "INSERT INTO stocks (user_id, symbol, shares) VALUES (:user, :symbol, :shares)",
                    user=session["user_id"],
                    symbol=symbol,
                    shares=shares,
                )
            # Otherwise, increase by the number of shares
            else:
                db.execute(
                    "UPDATE stocks SET shares = shares + :shares WHERE symbol = :symbol AND user_id = :id",
                    shares=shares,
                    symbol=symbol,
                    id=session["user_id"],
                )

            # Update the value of the user's cash to the new balance after the transaction
            balance = liquidity - cost
            db.execute(
                "UPDATE users SET cash = :cash WHERE id = :id",
                cash=balance,
                id=session["user_id"],
            )
            # Redirect user to the index screen
            flash("Stocks purchased successfuly")
            return redirect("/")
        else:
            return apology("you do not have enough cash for this transaction", 401)

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = :username",
            username=request.form.get("username"),
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("You are successfuly logged in")
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
        symbol = request.form.get("symbol")

        # Make sure there is symbol in the form
        if not symbol:
            return apology("must provide symbol", 403)

        # Lookup the symbol and return the quoted template
        stockInfo = lookup(symbol)

        # Inform the user if we couldn't find the symbol
        if stockInfo == None:
            return apology(f"couldn't find price for {symbol}", 404)

        return render_template(
            "quoted.html",
            name=stockInfo["name"],
            price=stockInfo["price"],
            symbol=stockInfo["symbol"],
        )

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username and password fields were submitted
        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)

        # Hash the password
        hash = generate_password_hash(password)

        # Make sure this username, combination doesn't exist
        rows = db.execute(
            "SELECT * FROM users WHERE username = :username", username=username
        )

        if len(rows) == 0:
            # Create user
            db.execute(
                "INSERT INTO users (username, hash) VALUES(:username, :hash)",
                username=username,
                hash=hash,
            )
            flash("Your account has been created successfuly")
            return render_template("login.html")

        # If the user exists, redirect to login also
        else:
            flash("User already exists, try to login instead")
            return render_template("login.html")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        type = "SELL"

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Ensure that both fields are valid
        if not symbol:
            return apology("must provide symbol", 403)
        elif not shares:
            return apology("must provide number of shares", 403)
        elif int(shares) < 1:
            return apology("number of shares must be greater than 1", 403)

        # Get the stock's info
        stockInfo = lookup(symbol)

        # Verify that the user has the amount of stock they submited
        userOwned = db.execute(
            "SELECT shares FROM stocks WHERE user_id = :id AND symbol = :symbol",
            id=session["user_id"],
            symbol=symbol,
        )

        userShares = userOwned[0]["shares"]
        if userShares < shares:
            return apology("You do not possess enough shares for this operation", 403)
        else:
            # Create a transaction for the trade
            db.execute(
                "INSERT INTO transactions (type, symbol, shares, price) VALUES (:type, :symbol, :shares, :price)",
                type=type,
                symbol=symbol,
                shares=shares,
                price=int(stockInfo["price"]),
            )

            # Register the last transaction in the trades table and associate it with the user id
            lastTransaction = db.execute(
                "SELECT id FROM transactions ORDER BY id DESC LIMIT 1"
            )

            db.execute(
                "INSERT INTO trades (trade_id, user_id) VALUES (:transaction, :user)",
                transaction=lastTransaction[0]["id"],
                user=session["user_id"],
            )

            # Update the user's stock
            db.execute(
                "UPDATE stocks SET shares = shares - :shares WHERE symbol = :symbol AND user_id = :id",
                shares=shares,
                symbol=symbol,
                id=session["user_id"],
            )

            # Update the user's cash balance
            revenue = shares * stockInfo["price"]
            db.execute(
                "UPDATE users SET cash = cash + :revenue WHERE id = :id",
                revenue=revenue,
                id=session["user_id"],
            )

            # Redirect user to the index screen
            flash("Stocks sold successfuly")
            return redirect("/")

    else:
        # List the available stocks for the user
        stocks = db.execute(
            "SELECT symbol FROM stocks WHERE user_id = :id", id=session["user_id"]
        )

        stockList = []
        for stock in stocks:
            stockList.append(stock["symbol"])

        return render_template("sell.html", stocks=stockList)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
