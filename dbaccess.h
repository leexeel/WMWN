#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>

MYSQL *connServer;
MYSQL_RES *resServer;
MYSQL_ROW rowServer;
MYSQL *conn;
MYSQL_RES *res;
MYSQL_ROW row;
MYSQL_TIME ts;

int serverAvailable;

void mysqlServerConn(int operatiune); //conexiune la server