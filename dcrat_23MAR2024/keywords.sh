dir=$1

cat "$dir" | grep -ie "keylogger" -e "host" -e "port" -e "http" -e "victim" -e "isconnected" -e "registry" -e "send" -e "connect" -e "receive" -e "get_" -e ".exe" -e ".com" -e "delete" -e "password" -e "ransom" -e "encryption" -e "crypt"

exit
