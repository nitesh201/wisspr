drop table if exists entries;
create table entries (
  uid integer primary key autoincrement,
  username text not null,
  password_hash text not null
);