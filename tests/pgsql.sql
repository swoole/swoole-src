DROP TABLE IF EXISTS weather;
CREATE TABLE weather (
        id SERIAL primary key NOT NULL,
        city character varying(80),
        temp_lo integer,
        temp_hi integer,
        prcp real,
        date date);
INSERT INTO weather(city, temp_lo, temp_hi, prcp, date) VALUES ('San Francisco', 46, 50, 0.25, '1994-11-27') RETURNING id;
INSERT INTO weather(city, temp_lo, temp_hi, prcp, date) VALUES ('Test2', 11, 22, 0.3, '1994-11-28') RETURNING id;

DROP TABLE IF EXISTS oid;
CREATE TABLE oid (
        id SERIAL primary key NOT NULL,
        oid oid);
