# nc.py
Python Netcat is a simple implementation of the versatile networking utility Netcat, allowing for communication between a client and a server over TCP. Inspired by the traditional Netcat tool, this script is implemented in Python and provides additional features such as SSL support and command execution capabilities. It can be used for various purposes, including remote command execution, file transfers, and establishing a command shell over a network connection. 

## Download
To download the Python Netcat script, you can use the following curl command:
```
curl -LO https://raw.githubusercontent.com/m4cr0m4l/nc.py/master/nc.py
```

Additionally, pre-built binaries are available in the [releases section](https://github.com/m4cr0m4l/nc.py/releases) for Windows, Linux, and macOS. These binaries are created using PyInstaller, so it is not necessary to have Python installed on your system to run the script. You can simply download the appropriate binary for your operating system and execute it directly.


## Usage
```
usage: nc.py [-h] [-c] [-e EXECUTE] [-l] [-v] [-s] [--ssl-cert SSL_CERT]
             [--ssl-key SSL_KEY] [--ssl-verify]
             [target] [port]

Python Netcat

positional arguments:
  target                specified IP
  port                  specified port

options:
  -h, --help            show this help message and exit
  -c, --command         initialize command shell
  -e, --execute EXECUTE
                        execute specified command
  -l, --listen          listen
  -v, --verbose         be verbose
  -s, --ssl             enable SSL
  --ssl-cert SSL_CERT   specify SSL certificate file
  --ssl-key SSL_KEY     specify SSL private key
  --ssl-verify          verify SSL certificates
```

## Examples
Start a command shell on port 8888:
```
nc.py -l -c -v 0.0.0.0 8888
```

Connect to a server at IP 192.168.1.10 on port 8888:
```
nc.py 192.168.1.10 8888
```

Execute a command on the server and return the output:
```
nc.py -l -e "cat /etc/passwd"
```

Send a file to the server:
```
nc.py 192.168.1.10 8888 < /etc/passwd
```

Upload a file to the server:
```
nc.py -l 0.0.0.0 8888 > file.txt
```
