CREATE ROLE notes_user WITH LOGIN CREATEDB PASSWORD '123';
CREATE SCHEMA notes_user AUTHORIZATION notes_user;
CREATE TABLE notes_user.notes (
    date DATE,
    text VARCHAR(1555),
    done BIT
);
ALTER TABLE notes_user.notes OWNER TO notes_user;