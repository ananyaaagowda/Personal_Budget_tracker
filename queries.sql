CREATE TABLE users(
id SERIAL PRIMARY KEY,
email VARCHAR(100) NOT NULL UNIQUE,
password VARCHAR(100)
);

CREATE TABLE INCOME(
	id serial primary key,
    user_id INTEGER REFERENCES users(id),
	source varchar(100),
	amount int,
	income_date date,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE EXPENSE(
	id serial primary key,
    user_id INTEGER REFERENCES users(id),
	category varchar(100),
	amount int,
	expense_date date,
	created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE BUDGET (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    budget_month DATE NOT NULL,
    budget_amount NUMERIC(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);