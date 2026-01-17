terminal_1: make clean
terminal_1: make
terminal_1: ./server
terminal_2: go build -o receiver_client_go receiver_client.go
terminal_2: ./receiver_client_go
terminal_2+x: python3 data_server.py --id x
