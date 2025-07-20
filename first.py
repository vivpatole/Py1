import socket
import threading
from tkinter import *

sniffing = False
sniffer_socket = None

def start_sniffing():
    global sniffing, sniffer_socket
    sniffing = True
    start_button.config(state=DISABLED)
    stop_button.config(state=NORMAL)

    ip_address = ip_entry.get().strip()

    def sniff():
        global sniffer_socket
        try:
            sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer_socket.bind((ip_address, 0))
            sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            while sniffing:
                raw_data, addr = sniffer_socket.recvfrom(65565)
                output.insert(END, f" Packet from {addr[0]} | {len(raw_data)} bytes\n")
                output.see(END)

        except Exception as e:
            output.insert(END, f" Error: {e}\n")
            output.see(END)

    threading.Thread(target=sniff, daemon=True).start()

def stop_sniffing():
    global sniffing, sniffer_socket
    sniffing = False
    start_button.config(state=NORMAL)
    stop_button.config(state=DISABLED)
    if sniffer_socket:
        sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sniffer_socket.close()
        sniffer_socket = None
        output.insert(END, " Sniffing stopped.\n")
        output.see(END)

app = Tk()
app.title("Socket-Based Network Sniffer")
app.geometry("600x400")
app.configure(bg="#f0f0f0")

Label(app, text="Enter Your IP Address:", bg="#f0f0f0", font=("Arial", 10)).pack(pady=5)
ip_entry = Entry(app, width=30)
ip_entry.insert(0, "192.168.23.167")  
ip_entry.pack()

start_button = Button(app, text="Start Sniffing", command=start_sniffing, bg="green", fg="white", width=15)
start_button.pack(pady=5)

stop_button = Button(app, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white", width=15, state=DISABLED)
stop_button.pack(pady=5)

output = Text(app, height=15, width=75)
output.pack(pady=10)

app.mainloop()