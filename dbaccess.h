MYSQL *connServer;
MYSQL_RES *resServer;
MYSQL_ROW rowServer;
MYSQL *conn;
MYSQL_RES *res;
MYSQL_ROW row;
MYSQL_TIME ts;

void mysqlServerConn(int operatiune); //conexiune la server