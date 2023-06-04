#include <mariadb/my_global.h>
#include <mariadb/mysql.h>
#include <stdio.h>
#include <stdlib.h>


MYSQL *con;

void connect_mysql_ubuntu(char* hostname, char* passwd, char* colname){
        con = mysql_init(NULL);
        if(con == NULL){
               fprintf(stderr, "%s\n", mysql_error(con));
                exit(1);
        }
        
        if(mysql_real_connect(con,"localhost",hostname,passwd,colname,0,NULL, 0)==NULL){
        	fprintf(stderr, "%s\n", mysql_error(con));
      	mysql_close(con);
      	exit(1);
  	}

}

int connect_query_mysql(char * con_query){
        if(mysql_query(con, con_query)){
                fprintf(stderr, "%s\n", mysql_error(con));
                mysql_close(con);
                exit(1);
                             
         }
        else {
		return 1;
        }
}

void result_query_mysql(char* domain[]){
        MYSQL_RES* result = mysql_store_result(con);
        unsigned int num_fields = mysql_num_fields(result);
        
	if(!result) printf("Couldn't get result set : %s\n", mysql_error(con));
        else{
                MYSQL_ROW row;
                while((row = mysql_fetch_row(result)) != NULL){
                        for(unsigned int i = 0; i < num_fields; i++) {
                            	domain[i] = row[i];
                        }
                         puts(" ");
                  }
                mysql_free_result(result);
        }
}


void end_mysql(){
	mysql_close(con);
  	exit(0);
}
