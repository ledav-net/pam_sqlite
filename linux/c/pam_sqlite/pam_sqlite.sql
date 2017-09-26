
drop table users;

create table users (
  login         varchar(20)     primary key,
  passwd        varchar(20)     not null,
  isexpired     char(1)         not null default 'n',
  neednewtok    char(1)         not null default 'n'
);
