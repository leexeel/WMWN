#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>

#include "dbaccess.h"

void mysqlServerConn(int operatiune){
    if(operatiune == 1){
        char *server = "192.168.10.17";
        char *user = "senzor";
        char *password = "senzor@db1234";
        char *database = "serverDB";
        connServer = mysql_init(NULL);
        printf("ne conectam la DB server");
        if (!mysql_real_connect(connServer, server, user, password, database, 0, NULL, 0)){
            printf("eroare la server");
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
