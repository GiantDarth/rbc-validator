#include <sqlite3.h>
#include <stdio.h>

int main(void) {

  sqlite3 *db;
  sqlite3_stmt *stmt;
  int patt = 0;
  int chunk = 0;
  char *err_message = 0;
  int rank = 0;

  // database file to open
  int rc = sqlite3_open("lookup_table.db", &db);

  if (rc != SQLITE_OK) {

    fprintf(stderr, "Can not open the database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
  } else {
    fprintf(stdout, "Database Opened successfully\n");
  }

  // create a sql statement, here we will create a table in the db, and insert some rows
  char *sql_query = "CREATE TABLE n64(rank INT PRIMARY KEY NOT NULL, hd1patt TEXT, hd2patt TEXT, hd3patt TEXT, hd4patt TEXT, hd5patt TEXT, hd6patt TEXT, hd7patt TEXT, chunk INT);"
                    "INSERT INTO n64 VALUES ('0',1000001,1000002,1000003,1000004,1000005,1000006,1000007,64);"
                    "INSERT INTO n64 VALUES ('1',1100001,1100002,1100003,1100004,1100005,1100006,1100007,64);"
                    "INSERT INTO n64 VALUES ('2',1000001,1000002,1000003,1000004,1000005,1000006,1000007,64);"
                    "INSERT INTO n64 VALUES ('3',1000001,1000002,1000003,1000004,1000005,1000006,1000007,64);"
                    "INSERT INTO n64 VALUES ('4',1000001,1000002,1000003,1000004,1000005,1000006,1000007,64);"
                    "INSERT INTO n64 VALUES ('5',1000001,1000002,1000003,1000004,1000005,1000006,1000007,64);"
                    "INSERT INTO n64 VALUES ('6',1000001,1000002,1000003,1000004,1000005,1000006,1000007,64);"
                    "INSERT INTO n64 VALUES ('7',1000001,1000002,1000003,1000004,1000005,1000006,1000007,64);";
  // execute the query
  rc = sqlite3_exec(db, sql_query, 0, 0, &err_message);

  // create another sql statement, creating the second pretend lookup table for ranks size 128
  sql_query = "CREATE TABLE n128(rank INT PRIMARY KEY NOT NULL, hd1patt TEXT, hd2patt TEXT, hd3patt TEXT, hd4patt TEXT, hd5patt TEXT, hd6patt TEXT, hd7patt TEXT, chunk INT);"
                    "INSERT INTO n128 VALUES ('0',1000001,1000002,1000003,1000004,1000005,1000006,1000007,128);"
                    "INSERT INTO n128 VALUES ('1',1100001,1100002,1100003,1100004,1100005,1100006,1100007,128);"
                    "INSERT INTO n128 VALUES ('2',1000001,1000002,1000003,1000004,1000005,1000006,1000007,128);"
                    "INSERT INTO n128 VALUES ('3',1000001,1000002,1000003,1000004,1000005,1000006,1000007,128);"
                    "INSERT INTO n128 VALUES ('4',1000001,1000002,1000003,1000004,1000005,1000006,1000007,128);"
                    "INSERT INTO n128 VALUES ('5',1000001,1000002,1000003,1000004,1000005,1000006,1000007,128);"
                    "INSERT INTO n128 VALUES ('6',1000001,1000002,1000003,1000004,1000005,1000006,1000007,128);"
                    "INSERT INTO n128 VALUES ('7',1000001,1000002,1000003,1000004,1000005,1000006,1000007,128);";

  // execute the query, should do error check here later
  rc = sqlite3_exec(db, sql_query, 0, 0, &err_message);


  printf("lets pull hamming distance 3 pattern for rank %d and the chunk size from table n128 ...\n",rank);

  // create another sql statement, here we are just going to do a select statement, and return Hamming
  // distance 3 pattern, and the chunk size. The ? is a placeholder for later when we will bind a value
  // to the statement.
  sql_query = "SELECT hd3patt,chunk from n128 where rank=?;";

  // prepare the statement
  sqlite3_prepare_v2(db, sql_query, -1, &stmt, NULL);

  // bind the variable to the statement
  rc = sqlite3_bind_int(stmt, 1, rank);

  if (rc != SQLITE_OK) {
    printf("Failed to bind parameter: %s\n\r", sqlite3_errstr(rc));
    sqlite3_close(db);
    return 1;
  }

  // execute the statement, this is different way of executing the statment than
  // we did above with sqlite3_exec. this is a more manual way
  sqlite3_step(stmt);

  // grab the pattern returned from the query, its in the 0th position
  patt = sqlite3_column_int(stmt, 0);
  printf("patt is: %d\n",patt);

  // grab the chunk size, the second column returned from the query, its in
  // the 1st position
  chunk = sqlite3_column_int(stmt, 1);
  printf("chunk is: %d\n",chunk);

  // destroy the query
  sqlite3_finalize(stmt);

  if (rc != SQLITE_OK ) {

    fprintf(stderr, "SQL error: %s\n", err_message);

    sqlite3_free(err_message);
    sqlite3_close(db);

    return 1;
  } else {
    fprintf(stdout, "Tables created successfully\n");
  }

  sqlite3_close(db);

  return 0;
}
