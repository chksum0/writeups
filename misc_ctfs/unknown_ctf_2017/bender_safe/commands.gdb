set architecture mips
set endian big
target remote 127.0.0.1:1234
b *0x00401c50
commands
  set $password = "AJAM1J7LKCCYAYMA"
  set *(char *) ($v1 + 0) = $password[0]
  set *(char *) ($v1 + 1) = $password[1]
  set *(char *) ($v1 + 2) = $password[2]
  set *(char *) ($v1 + 3) = $password[3]
  set *(char *) ($v1 + 4) = $password[4]
  set *(char *) ($v1 + 5) = $password[5]
  set *(char *) ($v1 + 6) = $password[6]
  set *(char *) ($v1 + 7) = $password[7]
  set *(char *) ($v1 + 8) = $password[8]
  set *(char *) ($v1 + 9) = $password[9]
  set *(char *) ($v1 + 10) = $password[10]
  set *(char *) ($v1 + 11) = $password[11]
  set *(char *) ($v1 + 12) = $password[12]
  set *(char *) ($v1 + 13) = $password[13]
  set *(char *) ($v1 + 14) = $password[14]
  set *(char *) ($v1 + 15) = $password[15]
  continue
end

continue
quit
