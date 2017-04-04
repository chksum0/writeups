use CGI;
use DBI;
use Digest::MD5 qw(md5_hex);
use Digest::SHA qw(sha256_hex);
use Crypt::Eksblowfish::Bcrypt qw(bcrypt_hash);
use Config::IniFiles;
use MIME::Base64;
# use Shadowd::Connector::CGI;

undef $/;
my $upload_dir = '/tmp/';

my $cfg = Config::IniFiles->new(-file => "../private/config.ini");
my $dbh = DBI->connect('DBI:mysql:database=ctf', 'ctf', $cfg->val('Database', 'Password'));

sub get_template {
	my $filename = shift;

	open (FILE, $filename);
	my $output = <FILE>;
	close(FILE);

	return $output;
}

sub print_template {
	my $filename = shift;

	print get_template($filename);
}

sub escape_string {
	my $input = shift;
	my @bad = ('\(', '\)', '\=', '\+', '\|', '\&', '\%', ';', 'union', 'select');

	foreach my $element (@bad) {
		$input =~ s/$element//si;
	}

	return $input;
}

sub gen_password {
	my @chars = ("A".."Z", "a".."z", "0".."9");

	my $string;
	$string .= $chars[rand @chars] for 1..30;

	return $string;
}

sub get_hash {
	my $input = shift;

	$input = bcrypt_hash({
		key_nul => 1,
		cost => 8,
		salt => '1234' x 4,
	}, $input);

	return sha256_hex($input);
}

sub do_gpg {
	my $path = shift;

	my $data1 = `gpg --list-packets $path`;

	if (!$data1) {
		return 'Invalid gpg pubkey file.';
	}

	my @data2 = split("\n", $data1);
	my @data3 = grep(/user ID packet/, @data2);

	if ($#data3 < 0) {
		return 'No user id found.';
	}

	my $user_id;

	if ($data3[0] =~ /\:user ID packet\: "(.*)"/) {
		my $id1 = $1;

		if (!$id1) {
			return 'User id is empty.';
		} elsif ($id1 =~ /<(.*?)>/) {
			$user_id = escape_string($1);
		} else {
			$user_id = escape_string($id1);
		}
	} else {
		return 'User id is strange.';
	}

	my $data4 = `gpg --import $path 2>&1`;
	my @data5 = split("\n", $data4);
	my @data6 = grep(/gpg: key/, @data5);

	if ($#data6 < 0) {
		return 'No key found.';
	}

	my $pub_id;

	if ($data6[0] =~ /gpg\: key ([\w]*)/) {
		$pub_id = $1;
	} else {
		return 'Key is strange.';
	}

	my $sth_select = $dbh->prepare("SELECT * FROM accounts WHERE user_id = '" . $user_id . "'");
	$sth_select->execute();

	if ($sth_select->err) {
		return "Could not execute database query.";
	}	

	my $msg;

	if (!$sth_select->rows) {
		my $password = gen_password();

		my $sth_insert = $dbh->prepare("INSERT INTO accounts (path, user_id, pass, activated) VALUES (?, ?, ?, false)");
		$sth_insert->execute($path, $user_id, get_hash($password));

		$msg = 'Hello ' . $user_id . ', here is your password: ' . $password . '. Your account has to be activated by an admin.';
	} else {
		$msg = 'Account already existing: </br>';

		while (my $ref = $sth_select->fetchrow_hashref()) {
			$msg .= '(' . $ref->{'id'} . ') ' . $user_id . ' </br>';
			$msg .= '[' . ($ref->{'path'} == $path ? 'same' : 'different') . ' key]</br>';
		}
	}

	my $base64_msg = encode_base64($msg);
	return `echo '$base64_msg' | base64 -d | gpg -r $pub_id -a --batch --always-trust --encrypt --ignore-valid-from`;
}

sub do_login {
	my $email = shift;
	my $password = shift;

	my $sth_select = $dbh->prepare("SELECT * FROM accounts WHERE user_id = ? AND pass = ? AND activated = true");
	$sth_select->execute($email, get_hash($password));

	return ($sth_select->rows > 0);
}

my $post_max = 1024 * 10;
$CGI::POST_MAX = $post_max;
my $query = new CGI;

print "Content-type: text/html\n\n";

my $content_length = defined $ENV{'CONTENT_LENGTH'} ? $ENV{'CONTENT_LENGTH'} : 0;
if ($content_length > $post_max) {
	print 'Too much data.';
	exit;
}

my $email = $query->param('email');
my $password = $query->param('password');

my %templates = (
	header => 'templates/header.html',
	footer => 'templates/footer.html',
	form => 'templates/form.html',
	error => $query->param('error')
);

print_template($templates{header});
print '<div class="output">';

if ($email && $password) {
	if (do_login($email, $password)) {
		print 'The administration key for the grades is ' . $cfg->val('CTF', 'Flag') . '.';
	} else {
		print 'Wrong login data or deactivated account.';
	}
} elsif ($email || $password) {
	print 'You have to enter an e-mail address and a password.';
}

if ($query->param('gpg_file')) {
	my $file = $query->upload('gpg_file');
	my $input = <$file>;

	# Secruti first!
	if ($input =~ /^([\w\s=..:;()!\/+-]*)$/s) {
		my $path = $upload_dir . md5_hex($input);

		open (UPLOADFILE, '>' . $path) or die $!;
		binmode UPLOADFILE;
		print UPLOADFILE $input;
		close UPLOADFILE;

		print do_gpg($path);
	} else {
		print 'Invalid gpg key. Please use an ASCII-armored format.';
	}
}

print '</div>';
print_template($templates{form});
print_template($templates{footer});
