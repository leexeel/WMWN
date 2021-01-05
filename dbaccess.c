#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>

#include "dbaccess.h"

void mysqlServerConn(int operatiune){
    if(operatiune == 1){
        char *server = "localhost";
        char *user = "root";
        char *password = ""; /* set me first */
        char *database = "serverDB";
        connServer = mysql_init(NULL);
        if (!mysql_real_connect(connServer, server, user, password, database, 0, NULL, 0)){
            fprintf(stderr, "%s\n", mysql_error(connServer));
            serverAvailable = 0;
            //exit(1);
        } else {
            serverAvailable = 1;
        }
    } else {
        mysql_close(connServer);
        serverAvailable = 0;
    }
}
