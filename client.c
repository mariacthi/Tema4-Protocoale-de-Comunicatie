#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"

#define REGISTER "/api/v1/tema/auth/register/"
#define LOGIN "/api/v1/tema/auth/login/"
#define ACCESS "/api/v1/tema/library/access/"
#define BOOKS "/api/v1/tema/library/books/"
#define LOGOUT "/api/v1/tema/auth/logout/"
#define JSON "application/json"
#define HOST "34.246.184.49"
#define PORT 8080
#define ALPHABET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

void remove_newline(char *s)
{
    if (s[strlen(s) - 1] == '\n') {
        s[strlen(s) - 1] = '\0';
    }
}

int verify_letters(char *credential)
{
    /* verifies that the credential doesn't have any letters
     * in it (useful for id and page_count verification)
     */
    for (int i = 0; i < strlen(credential); i++) {
        if (strchr(ALPHABET, credential[i]) != NULL) {
            return 0;
        }
    }
    return 1;
}

int read_credential(char *credential, char *name, int verify)
{
    /* reads the input for a field with the name transmitted
     * as a parameter and verifies the validity of the data
     * (return value is 1 for when it finds an error,
     * otherwise it is 0)
     *
     * if verify is 0 the function is used for fields where
     * the content doesn't matter, as long as it's not empty
     * if verify is 1 the function is used for username and password
     * which aren't allowed to have spaces
     * if verify is 2 the function is used for verifying fields
     * that should only contain valid numbers (id and page_count)
     */
    printf("%s=", name);
    fgets(credential, LINELEN, stdin);
    remove_newline(credential);

    if (strlen(credential) == 0) {
        return 1;
    }

    if (verify == 1) {
        if (strchr(credential, ' ') != NULL) {
            return 1;
        }
    } else if (verify == 2) {
        if (credential[0] == '0' || verify_letters(credential) == 0) {
            return 1;
        }
    }

    return 0;
}

void send_JSON(int sockfd, char *username, char *password, char *url)
{
    /* sends JSON with username and password to the server
     * for register and login functions
     */
    JSON_Value *val = json_value_init_object();
    JSON_Object *object = json_value_get_object(val);

    json_object_set_string(object, "username", username);
    json_object_set_string(object, "password", password);
    char *final_data = json_serialize_to_string_pretty(val);

    char *message = compute_post_request(HOST, url, JSON, &final_data, 1,
                                         NULL, 1, NULL);
    send_to_server(sockfd, message);

    free(message);
    json_free_serialized_string(final_data);
    json_value_free(val);
}

void register_data(int sockfd)
{
    /* uses the variable "errors" to store the number of times an error was
     * found when trying to read the username and password (the checker
     * needs to read all input data before giving the error message)
     */
    char *username = calloc(BUFLEN, sizeof(char));
    int errors = read_credential(username, "username", 1);

    char *password = calloc(BUFLEN, sizeof(char));
    errors += read_credential(password, "password", 1);

    if (errors) {
        printf("Eroare: Te rog sa introduci date valide si fara spatii!\n");
        return;
    }

    /* no errors were found => sends the credentials to the server*/
    send_JSON(sockfd, username, password, REGISTER);

    /* checks the response from the server */
    char *response = receive_from_server(sockfd);
    if (strncmp(response, "HTTP/1.1 201 Created", 20) == 0) {
        printf("Succes: Utilizator inregistrat cu succes!\n");
    } else if (strncmp(response, "HTTP/1.1 400 Bad Request", 24) == 0) {
        printf("Eroare: Username-ul este deja utilizat de catre altcineva!\n");
    } else {
        printf("Eroare: Ceva s-a intamplat la crearea user-ului!\n");
    }

    free(response);
    free(username);
    free(password);
}

void login(char **login_cookies, int sockfd)
{
    /* uses the variable "errors" to store the number of times an error was
    * found when trying to read the username and password (the checker
    * needs to read all input data before giving the error message)
    */
    char *username = calloc(BUFLEN, sizeof(char));
    int errors = read_credential(username, "username", 1);

    char *password = calloc(BUFLEN, sizeof(char));
    errors += read_credential(password, "password", 1);

    if (errors) {
        printf("Eroare: Te rog sa introduci date valide si fara spatii!\n");
        return;
    }

    /* no errors were found => sends the credentials to the server*/
    send_JSON(sockfd, username, password, LOGIN);

    /* checks the response from the server */
    char *response = receive_from_server(sockfd);
    if (strncmp(response, "HTTP/1.1 200 OK", 15) == 0) {
        /* extracts the cookie from the server response */
        char *p = strstr(response, "connect.sid=");
        p = strtok(p, ";");
        *login_cookies = strdup(p);

        printf("Succes: Utilizatorul a fost logat cu succes!\n");
    } else if (strncmp(response, "HTTP/1.1 400 Bad Request", 24) == 0) {
        printf("Eroare: Username sau parola gresita\n");
    } else {
        printf("Eroare: Ceva s-a intamplat la logarea user-ului!\n");
    }

    free(response);
    free(username);
    free(password);
}

char* enter_library(char *login_cookies, int sockfd)
{
    /* sends a GET request to the server */
    char *message = compute_get_delete_request (HOST, ACCESS, NULL,
                                                &login_cookies, 1,
                                                NULL, "GET");
    send_to_server(sockfd, message);
    free(message);

    char *token = NULL;

    /* checks the response from the server */
    char *response = receive_from_server(sockfd);
    if (strncmp(response, "HTTP/1.1 200 OK", 15) == 0) {
        /* extracts the token from the server response */
        token = strstr(response, "token");
        token = strtok(token + strlen("\"token\":"), "\"");
        printf("Succes: Utilizatorul a obtinut acces la biblioteca cu succes!\n");
    }
    else {
        printf("Eroare: Nu se poate accesa biblioteca\n");
    }

    free(response);
    return (token == NULL ? NULL : strdup(token));
}

void get_json(char *response)
{
    /* extracts the book(s) information from the response
     * (this function is used either for get_books operation
     * or get_book operation) */
    char *books_info;
    if (strstr(response, "[") != NULL) {
        /* for get_books function */
        books_info = strstr(response, "[");
    } else {
        /* for get_book function, where the response doesn't contain "[]" */
        books_info = strstr(response, "{");
    }

    /* prints the data */
    JSON_Value *val = json_parse_string(books_info);
    books_info = json_serialize_to_string_pretty(val);
    printf("%s\n", books_info);

    json_value_free(val);
    free(books_info);
}

void get_books(char *token, int sockfd)
{
    /* sends a GET request to the server */
    char *message = compute_get_delete_request(HOST, BOOKS, NULL, NULL, 1,
                                               token, "GET");
    send_to_server(sockfd, message);
    free(message);

    /* checks the response from the server */
    char *response = receive_from_server(sockfd);
    if (strncmp(response, "HTTP/1.1 200 OK", 15) == 0) {
        get_json(response);
    } else if (strncmp(response, "HTTP/1.1 403 Forbidden", 20) == 0) {
        printf("Eroare: Nu ai acces la biblioteca!\n");
    } else {
        printf("Eroare: Nu se poate accesa biblioteca!\n");
    }

    free(response);
}

void get_book(char *token, int sockfd)
{
    /* reads the id of the book */
    char *id = calloc(BUFLEN, sizeof(char));
    if (read_credential(id, "id", 2)) {
        printf("Eroare: Te rog sa introduci un id valid!\n");
        return;
    }

    /* creates the url address for the GET request */
    char *adress = malloc(LINELEN * sizeof(char));
    sprintf(adress, "%s%s", BOOKS, id);

    /* sends the GET request */
    char *message = compute_get_delete_request(HOST, adress, NULL, NULL, 1,
                                               token, "GET");
    send_to_server(sockfd, message);
    free(message);

    /* checks the response from the server*/
    char *response = receive_from_server(sockfd);
    if(strncmp(response, "HTTP/1.1 200 OK", 15) == 0) {
        get_json(response);
    } else if(strncmp(response, "HTTP/1.1 404 Not Found", 22) == 0) {
        printf("Eroare: Id-ul cerut este invalid!\n");
    } else if(strncmp(response, "HTTP/1.1 403 Forbidden", 20) == 0) {
        printf("Eroare: Nu ai acces la biblioteca!\n");
    } else {
        printf("Eroare: Nu se poate accesa biblioteca!\n");
    }

    free(response);
    free(adress);
    free(id);
}

void add_book(char *token, int sockfd)
{
    /* reads all the necessary fields for this operation and uses the
     * variable errors to store the number of times an error was
     * found when trying to read the data
     */
    char *title = calloc(BUFLEN, sizeof(char));
    int errors = read_credential(title, "title", 0);

    char *author = calloc(BUFLEN, sizeof(char));
    errors += read_credential(author, "author", 0);

    char *genre = calloc(BUFLEN, sizeof(char));
    errors += read_credential(genre, "genre", 0);

    char *publisher = calloc(BUFLEN, sizeof(char));
    errors += read_credential(publisher, "publisher", 0);

    char *page_count = calloc(BUFLEN, sizeof(char));
    errors += read_credential(page_count, "page_count", 2);

    if (errors) {
        printf("Eroare: Te rog sa introduci date valide!\n");
        return;
    }

    /* prepares the JSON object */
    JSON_Value *val = json_value_init_object();
    JSON_Object *object = json_value_get_object(val);

    json_object_set_string(object, "title", title);
    free(title);

    json_object_set_string(object, "author", author);
    free(author);

    json_object_set_string(object, "genre", genre);
    free(genre);

    json_object_set_string(object, "publisher", publisher);
    free(publisher);

    json_object_set_number(object, "page_count", atoi(page_count));
    free(page_count);

    char *final_data = json_serialize_to_string_pretty(val);

    /* sends the POST request */
    char *message = compute_post_request(HOST, BOOKS, JSON, &final_data,
                                         1, NULL, 1, token);
    send_to_server(sockfd, message);
    free(message);

    /* checks the response from the server */
    char *response = receive_from_server(sockfd);
    if(strncmp(response, "HTTP/1.1 200 OK", 15) == 0) {
        printf("Succes: Cartea a fost adaugata cu succes!\n");
    } else if(strncmp(response, "HTTP/1.1 403 Forbidden", 22) == 0) {
        printf("Eroare: Nu ai acces la biblioteca!\n");
    } else {
        printf("Eroare: Ceva s-a intamplat la adaugarea cartii!\n");
    }

    json_free_serialized_string(final_data);
    json_value_free(val);
    free(response);
}

void delete_book(char *token, int sockfd)
{
    /* reads the id of the book */
    char *id = calloc(BUFLEN, sizeof(char));
    if (read_credential(id, "id", 2)) {
        printf("Eroare: Te rog sa introduci un id valid!\n");
        return;
    }

    /* creates the url address for the DELETE request */
    char *adress = malloc(LINELEN * sizeof(char));
    sprintf(adress, "%s%s", BOOKS, id);

    /* sends the DELETE request */
    char *message = compute_get_delete_request(HOST, adress, NULL, NULL, 1,
                                               token, "DELETE");
    send_to_server(sockfd, message);
    free(message);
    free(adress);

    /*checks the response from the server */
    char *response = receive_from_server(sockfd);
    if (strncmp(response, "HTTP/1.1 200 OK", 15) == 0) {
        printf("Succes: Cartea cu id %d a fost stearsa cu succes!\n", atoi(id));
    } else if (strncmp(response, "HTTP/1.1 403 Forbidden", 22) == 0) {
        printf("Eroare: Nu ai acces la biblioteca!\n");
    } else {
        printf("Eroare: Id-ul este invalid!\n");
    }

    free(id);
    free(response);
}

void logout(char *login_cookies, char *token, int sockfd)
{
    /* sends the GET request */
    char *message = compute_get_delete_request(HOST, LOGOUT, NULL,
                                               &login_cookies, 1,
                                               token, "GET");
    send_to_server(sockfd, message);
    free(message);

    /* checks the response from the server */
    char *response = receive_from_server(sockfd);
    if (strncmp(response, "HTTP/1.1 200 OK", 15) == 0) {
        printf("Succes: Utilizatorul s-a delogat cu succes!\n");
    } else if (strncmp(response, "HTTP/1.1 401 Unauthorized", 25) == 0) {
        printf("Eroare: Nu sunteti logat!\n");
    } else {
        printf("Eroare: Ceva s-a intamplat la delogarea user-ului\n");
    }

    free(response);
}

int main(int argc, char *argv[])
{
    char *login_cookies = NULL;
    char *token = NULL;
    int sockfd;

    char *command = malloc(LINELEN * sizeof(char));
    while (1) {
        sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);

        memset(command, 0, LINELEN);
        fgets(command, LINELEN, stdin);
        remove_newline(command);

        if (strcmp(command, "register") == 0) {
            if (login_cookies != NULL) {
                printf("Eroare: Esti deja conectat!\n");
            } else {
               register_data(sockfd);
            }
        } else if (strcmp(command, "login") == 0) {
            if (login_cookies != NULL) {
                printf("Eroare: Esti deja logat!\n");
            } else {
                login(&login_cookies, sockfd);
            }
        } else if (strcmp(command, "enter_library") == 0) {
            if (login_cookies == NULL) {
                printf("Eroare: Pentru a accesa biblioteca, trebuie sa fii autentificat!\n");
            } else {
                token = enter_library(login_cookies, sockfd);
            }
        } else if (strcmp(command, "get_books") == 0) {
            if (login_cookies == NULL) {
                printf("Eroare: Pentru a afla detalii despre carti, trebuie sa fii autentificat!\n");
            } else {
                get_books(token, sockfd);
            }
        } else if (strcmp(command, "get_book") == 0) {
            if (login_cookies == NULL) {
                printf("Eroare: Pentru a afla detalii despre o anumita carte, trebuie sa fii autentificat!\n");
            } else {
                get_book(token, sockfd);
            }
        } else if (strcmp(command, "add_book") == 0) {
            if (login_cookies == NULL) {
                printf("Eroare: Pentru a adauga o carte, trebuie sa fii autentificat!\n");
            } else {
                add_book(token, sockfd);
            }
        } else if (strcmp(command, "delete_book") == 0) {
            if (login_cookies == NULL) {
                printf("Eroare: Pentru a sterge o carte, trebuie sa fii autentificat!\n");
            } else {
                delete_book(token, sockfd);
            }
        } else if (strcmp(command, "logout") == 0) {
            if(login_cookies == NULL) {
                printf("Eroare: Nu esti autentificat!\n");
            } else {
                logout(login_cookies, token, sockfd);

                /* making sure the memory is freed and the two parameters
                 * are set to NULL again so the user would have to log in
                 * again to access the data
                 */
                free(login_cookies);
                login_cookies = NULL;
                free(token);
                token = NULL;
            }
        } else if (strcmp(command, "exit") == 0) {
            close(sockfd);
            login_cookies != NULL ? free(login_cookies) : 1;
            token != NULL ? free(token) : 1;
            break;
        } else {
            printf("Eroare: comanda inexistenta!\n");
        }

    }
    free(command);
    free(login_cookies);
    free(token);

    return 0;
}