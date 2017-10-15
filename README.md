# SQLDatabaseServerClient

This software is .Net 4.5 client library to access www.sqldatabase.net database and cache server. The server program can be downloaded
directly from the website.

A single file ServerClient.cs contains all the neccessary code to access the server, the file can be added in your own project, 
it has been tested and used in windows forms or asp.net web forms application.

The project is Visual Studio 2015 solution.

If upgrading from Embedded database library http://www.sqldatabase.net/features.aspx then first create an empty database using the 
same database name as your existing embedded database. Database can be created using either the utility class or Create Database command 
and after creating the database replace the file on server data folder with your existing embedded database file, same can 
be done with each schema file. Once all files are replaced restart the server.
