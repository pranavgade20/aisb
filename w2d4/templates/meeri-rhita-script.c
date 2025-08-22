#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

/**
 

    main - Writes the current user's login name to a file named "username.txt".*

Return: 0 on success, 1 on failure.*/int main(void)
{
    // The file pointer for the output file
    FILE file_pointer;

    // The character array to hold the username
    charusername;

    // Open the file "username.txt" in write mode ("w").
    // If the file doesn't exist, it will be created. If it does, its contents
    // will be erased before writing.
    file_pointer = fopen("meeri-rhita", "w");

    // Check if the file was opened successfully.
    // fopen() returns NULL if it fails.
    if (file_pointer == NULL)
    {
        fprintf(stderr, "Error: Could not open file for writing.\n");
        return (1); // Exit with an error code
    }

    // Get the username using the getlogin() function.
    // It returns a pointer to a string containing the username.
    // It might return NULL if it can't determine the user.
    username = getlogin();

    // Check if the username was retrieved successfully.
    if (username == NULL)
    {
        fprintf(stderr, "Error: Could not get username.\n");
        fclose(file_pointer); // Close the file before exiting
        return (1);
    }

    // Use fprintf() to write the string (the username) to the file.
    // The syntax is similar to printf(), but the first argument is
    // the file pointer.
    fprintf(file_pointer, "Hello, %s!\n", username);

    // Close the file to ensure all data is written to disk and
    // to free up system resources.
    fclose(file_pointer);

    printf("Username has been written to username.txt\n");

    return (0); // Exit successfully
}
